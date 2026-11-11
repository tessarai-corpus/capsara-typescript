/** Capsa decryption utilities for client-side decryption of API responses. */

import * as crypto from 'crypto';
import { decryptAES, decryptMasterKey } from '../crypto/primitives.js';
import { buildCanonicalString, verifyCapsaSignature } from '../crypto/signatures.js';
import { calculateKeyFingerprint, calculatePrivateKeyFingerprint } from '../crypto/key-generator.js';
import { CapsaraCapsaError } from '../../errors/capsa-error.js';
import { CapsaraError } from '../../errors/capsara-error.js';
import type { Capsa, CapsaStatus, KeychainEntry, EncryptedFile, CapsaMetadata } from '../../types/index.js';

function fingerprintOrUndefined(privateKey: string): string | undefined {
  try {
    return calculatePrivateKeyFingerprint(privateKey);
  } catch {
    return undefined;
  }
}

export interface DecryptedCapsa {
  id: string;
  creator: string;
  createdAt: string;
  updatedAt: string;
  status: CapsaStatus | null | undefined;

  subject?: string;
  body?: string;
  structured?: Record<string, unknown>;

  files: EncryptedFile[];

  accessControl: {
    expiresAt?: string;
  };

  _masterKey: Buffer;

  clearMasterKey(): void;

  keychain: {
    algorithm: string;
    keys: KeychainEntry[];
  };

  signature: {
    algorithm: string;
    protected: string;
    payload: string;
    signature: string;
  };

  metadata?: CapsaMetadata;

  stats: {
    totalSize: number;
    fileCount: number;
    lastAccessedAt?: string;
  };

  _encrypted: Capsa;
}

export interface DecryptCapsaOptions {
  partyId?: string;
  previousPrivateKeys?: readonly string[];
}

function signatureError(capsa: Capsa, reason: string): CapsaraCapsaError {
  return new CapsaraCapsaError(
    `Signature verification failed: ${reason} (capsa: ${capsa.id}, creator: ${capsa.creator}).`,
    'SIGNATURE_VERIFICATION_FAILED',
    0,
    { capsaId: capsa.id }
  );
}

export function verifyCreatorSignature(capsa: Capsa): void {
  const creatorPublicKey = capsa.creatorPublicKey;
  if (!creatorPublicKey || typeof creatorPublicKey !== 'string') {
    throw new CapsaraCapsaError(
      `Capsa ${capsa.id} has no creator public key; its signature cannot be verified.`,
      'SIGNATURE_KEY_MISSING',
      0,
      { capsaId: capsa.id }
    );
  }

  const creatorEntry = capsa.keychain?.keys?.find((key) => key.party === capsa.creator);
  if (creatorEntry?.fingerprint) {
    let actual: string;
    try {
      actual = calculateKeyFingerprint(creatorPublicKey);
    } catch {
      throw signatureError(capsa, 'creator public key cannot be parsed');
    }
    if (actual !== creatorEntry.fingerprint) {
      throw new CapsaraCapsaError(
        `Creator public key on capsa ${capsa.id} does not match the creator's keychain fingerprint.`,
        'SIGNATURE_KEY_MISMATCH',
        0,
        { capsaId: capsa.id, expected: creatorEntry.fingerprint, actual }
      );
    }
  }

  if (!capsa.signature || typeof capsa.signature !== 'object' || !capsa.signature.signature) {
    throw signatureError(capsa, 'signature is missing');
  }

  const signatureLength = Buffer.from(capsa.signature.signature, 'base64url').length;
  if (signatureLength !== 512) {
    throw signatureError(capsa, `expected a 512-byte signature, got ${signatureLength} bytes`);
  }

  let valid: boolean;
  try {
    const canonicalString = buildCanonicalString({
      packageId: capsa.id,
      totalSize: capsa.totalSize,
      algorithm: capsa.keychain.algorithm,
      creatorPartyId: capsa.creator,
      creatorKeyFingerprint: calculateKeyFingerprint(creatorPublicKey),
      files: capsa.files,
      structuredIV: capsa.structuredIV,
      subjectIV: capsa.subjectIV,
      bodyIV: capsa.bodyIV,
    });
    valid = verifyCapsaSignature(capsa.signature, canonicalString, creatorPublicKey);
  } catch (error) {
    throw signatureError(capsa, error instanceof Error ? error.message : String(error));
  }

  if (!valid) {
    throw signatureError(capsa, 'capsa data does not match the signature');
  }
}

function selectPrivateKey(
  capsa: Capsa,
  entry: KeychainEntry,
  privateKey: string,
  previousPrivateKeys: readonly string[]
): string {
  const wanted = entry.fingerprint;
  if (wanted) {
    for (const candidate of [privateKey, ...previousPrivateKeys]) {
      const fingerprint = fingerprintOrUndefined(candidate);
      if (fingerprint === undefined) {
        throw new CapsaraError('A configured private key is not a usable RSA private key PEM.', 'INVALID_PRIVATE_KEY', 0, {
          capsaId: capsa.id,
        });
      }
      if (fingerprint === wanted) {
        return candidate;
      }
    }
  }

  throw new CapsaraCapsaError(
    `None of the configured private keys matches the key capsa ${capsa.id} was encrypted to. ` +
      'If this account rotated its key, add the earlier private key with addPreviousPrivateKey().',
    'PRIVATE_KEY_NOT_AVAILABLE',
    0,
    { capsaId: capsa.id, fingerprint: wanted ?? null }
  );
}

function notInKeychain(capsa: Capsa, message: string): CapsaraCapsaError {
  return new CapsaraCapsaError(message, 'NOT_IN_KEYCHAIN', 0, { capsaId: capsa.id });
}

function findCallerEntry(capsa: Capsa, partyId: string | undefined): KeychainEntry {
  const keys = Array.isArray(capsa.keychain?.keys) ? capsa.keychain.keys : [];
  if (keys.length === 0) {
    throw notInKeychain(capsa, 'Capsa keychain has no entries. Cannot decrypt.');
  }

  if (partyId) {
    const entry =
      keys.find((key) => key.party === partyId) ??
      keys.find((key) => key.actingFor?.includes(partyId));
    if (!entry) {
      throw notInKeychain(capsa, `Party ${partyId} not found in capsa keychain. Cannot decrypt.`);
    }
    return entry;
  }

  if (keys.length !== 1) {
    throw new CapsaraCapsaError(
      `Capsa keychain has ${keys.length} entries and no party ID was given. Cannot pick the caller's entry.`,
      'PRIVATE_KEY_NOT_AVAILABLE',
      0,
      { capsaId: capsa.id, fingerprint: null }
    );
  }
  return keys[0]!;
}

interface DecryptedContent {
  subject?: string;
  body?: string;
  structured?: Record<string, unknown>;
}

function decryptContent(capsa: Capsa, masterKey: Buffer): DecryptedContent {
  let subject: string | undefined;
  let body: string | undefined;
  let structured: Record<string, unknown> | undefined;

  if (capsa.encryptedSubject && capsa.subjectIV) {
    if (!capsa.subjectAuthTag) {
      // eslint-disable-next-line no-console
      console.warn(
        'WARNING: encryptedSubject missing authTag - skipping decryption for security'
      );
    } else {
      const subjectBuffer = decryptAES(
        capsa.encryptedSubject,
        masterKey,
        capsa.subjectIV,
        capsa.subjectAuthTag
      );
      subject = subjectBuffer.toString('utf-8');
    }
  }

  if (capsa.encryptedBody && capsa.bodyIV) {
    if (!capsa.bodyAuthTag) {
      // eslint-disable-next-line no-console
      console.warn(
        'WARNING: encryptedBody missing authTag - skipping decryption for security'
      );
    } else {
      const bodyBuffer = decryptAES(
        capsa.encryptedBody,
        masterKey,
        capsa.bodyIV,
        capsa.bodyAuthTag
      );
      body = bodyBuffer.toString('utf-8');
    }
  }

  if (capsa.encryptedStructured && capsa.structuredIV) {
    if (!capsa.structuredAuthTag) {
      // eslint-disable-next-line no-console
      console.warn(
        'WARNING: encryptedStructured missing authTag - skipping decryption for security'
      );
    } else {
      const structuredBuffer = decryptAES(
        capsa.encryptedStructured,
        masterKey,
        capsa.structuredIV,
        capsa.structuredAuthTag
      );
      structured = JSON.parse(structuredBuffer.toString('utf-8')) as Record<
        string,
        unknown
      >;
    }
  }

  return { subject, body, structured };
}

export function decryptCapsa(
  capsa: Capsa,
  privateKey: string,
  options: DecryptCapsaOptions = {}
): DecryptedCapsa {
  verifyCreatorSignature(capsa);

  if (!privateKey || typeof privateKey !== 'string' || !privateKey.includes('BEGIN') || !privateKey.includes('PRIVATE KEY')) {
    throw new CapsaraError('The current private key is not a usable RSA private key PEM.', 'INVALID_PRIVATE_KEY', 0, {
      capsaId: capsa.id,
    });
  }

  const keychainEntry = findCallerEntry(capsa, options.partyId);

  if (!keychainEntry.encryptedKey) {
    throw new CapsaraCapsaError(
      `Party ${keychainEntry.party} has no encrypted key in keychain. This party may be a delegated recipient without direct access.`,
      'NO_ENCRYPTED_KEY',
      0,
      { capsaId: capsa.id }
    );
  }

  const encryptedKeyBuffer = Buffer.from(keychainEntry.encryptedKey, 'base64url');
  if (encryptedKeyBuffer.length !== 512) {
    throw new CapsaraCapsaError(
      `Encrypted key length validation failed: expected 512 bytes (RSA-4096), got ${encryptedKeyBuffer.length} bytes (capsa: ${capsa.id}, party: ${keychainEntry.party}). Possible data corruption.`,
      'INVALID_ENCRYPTED_KEY',
      0,
      { capsaId: capsa.id }
    );
  }

  const selectedKey = selectPrivateKey(capsa, keychainEntry, privateKey, options.previousPrivateKeys ?? []);

  let masterKey: Buffer;
  try {
    masterKey = decryptMasterKey(keychainEntry.encryptedKey, selectedKey);
  } catch (error) {
    const originalMessage = error instanceof Error ? error.message : String(error);
    const failure = new CapsaraCapsaError(
      `RSA master key decryption failed: ${originalMessage} (capsa: ${capsa.id}, party: ${keychainEntry.party}, encryptedKeyLength: ${encryptedKeyBuffer.length})`,
      'KEY_DECRYPTION_FAILED',
      0,
      { capsaId: capsa.id }
    );
    failure.cause = error;
    throw failure;
  }

  if (masterKey.length !== 32) {
    const length = masterKey.length;
    masterKey.fill(0);
    throw new CapsaraCapsaError(
      `Master key size validation failed: expected 32 bytes (AES-256), got ${length} bytes. RSA decryption may have succeeded with wrong key.`,
      'KEY_DECRYPTION_FAILED',
      0,
      { capsaId: capsa.id }
    );
  }

  let content: DecryptedContent;
  try {
    content = decryptContent(capsa, masterKey);
  } catch (error) {
    masterKey.fill(0);
    const failure = new CapsaraCapsaError(
      `Failed to decrypt the content of capsa ${capsa.id}: ${error instanceof Error ? error.message : String(error)}`,
      'CONTENT_DECRYPTION_FAILED',
      0,
      { capsaId: capsa.id }
    );
    failure.cause = error;
    throw failure;
  }
  const { subject, body, structured } = content;

  const decryptedCapsa: DecryptedCapsa = {
    id: capsa.id,
    creator: capsa.creator,
    createdAt: capsa.createdAt,
    updatedAt: capsa.updatedAt,
    status: capsa.status,
    subject,
    body,
    structured,
    files: capsa.files,
    accessControl: capsa.accessControl,
    keychain: capsa.keychain,
    signature: capsa.signature,
    metadata: capsa.metadata,
    stats: {
      totalSize: capsa.totalSize,
      fileCount: capsa.files?.length ?? 0,
    },
    _encrypted: capsa,
    _masterKey: masterKey, // Placeholder, will be redefined as non-enumerable
    clearMasterKey: function() {
    }
  };

  Object.defineProperty(decryptedCapsa, '_masterKey', {
    value: masterKey,
    enumerable: false,   // Hidden from enumeration
    writable: false,     // Immutable
    configurable: true   // Allow clearMasterKey() to replace with zeroed buffer
  });

  decryptedCapsa.clearMasterKey = function() {
    if (this._masterKey && this._masterKey.length > 0) {
      crypto.randomFillSync(this._masterKey);

      Object.defineProperty(this, '_masterKey', {
        value: Buffer.alloc(0),
        enumerable: false,
        writable: false,
        configurable: false  // Lock down after clearing
      });
    }
  };

  return decryptedCapsa;
}

export function decryptFilename(
  encryptedFilename: string,
  masterKey: Buffer,
  iv: string,
  authTag: string
): string {
  if (!authTag || authTag.trim() === '') {
    throw new Error(
      'SECURITY ERROR: authTag is required for filename decryption. Missing authTag indicates potential tampering.'
    );
  }

  try {
    const filenameBuffer = decryptAES(encryptedFilename, masterKey, iv, authTag);
    return filenameBuffer.toString('utf-8');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Failed to decrypt filename: ${message}`, { cause: error });
  }
}
