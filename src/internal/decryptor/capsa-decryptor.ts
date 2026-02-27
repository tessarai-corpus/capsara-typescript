/** Capsa decryption utilities for client-side decryption of API responses. */

import * as crypto from 'crypto';
import { decryptAES, decryptMasterKey } from '../crypto/primitives.js';
import { buildCanonicalString, verifyCapsaSignature } from '../crypto/signatures.js';
import { decompressData } from '../crypto/compression.js';
import type { Capsa, KeychainEntry, EncryptedFile, CapsaMetadata } from '../../types/index.js';

export interface DecryptedCapsa {
  id: string;
  creator: string;
  createdAt: string;
  updatedAt: string;
  status: 'active' | 'expired';

  // Decrypted fields
  subject?: string;
  body?: string;
  structured?: Record<string, unknown>;

  // File metadata (still encrypted files)
  files: EncryptedFile[];

  // Access control
  accessControl: {
    expiresAt?: string;
  };

  /**
   * Cached AES-256 master key, avoids repeated RSA-4096 decryption per file.
   * Non-enumerable to prevent accidental serialization (JSON.stringify, spread, logging).
   * Scoped to this capsa only; does not compromise other capsas or the party's private key.
   * Call clearMasterKey() when done with file operations.
   */
  _masterKey: Buffer;

  /** Securely clears the master key from memory. */
  clearMasterKey(): void;

  // Keychain info
  keychain: {
    algorithm: string;
    keys: KeychainEntry[];
  };

  // Signature
  signature: {
    algorithm: string;
    protected: string;
    payload: string;
    signature: string;
  };

  // Public metadata (unencrypted)
  metadata?: CapsaMetadata;

  // Stats
  stats: {
    totalSize: number;
    fileCount: number;
    lastAccessedAt?: string;
  };

  // Original encrypted capsa (for reference)
  _encrypted: Capsa;
}

function findKeychainEntry(
  capsa: Capsa,
  partyId: string
): KeychainEntry | null {
  return capsa.keychain.keys.find((key: KeychainEntry) => key.party === partyId) || null;
}

function findDelegateEntry(
  capsa: Capsa,
  partyId: string
): KeychainEntry | null {
  return (
    capsa.keychain.keys.find(
      (key: KeychainEntry) => key.actingFor && key.actingFor.includes(partyId)
    ) || null
  );
}

/**
 * Decrypt capsa using party's private key
 *
 * SECURITY FEATURES:
 * - Verifies capsa signature before decryption
 * - Requires auth tags for all AES-GCM decryption
 * - Validates keychain entry exists
 *
 * NOTE: partyId is optional. If not provided, uses the first keychain entry
 * (which is the authenticated party's key when retrieved from API).
 *
 * @param capsa - Encrypted capsa from API
 * @param privateKey - Party's RSA private key in PEM format
 * @param partyId - Party ID (optional - auto-detected from keychain if omitted)
 * @param creatorPublicKey - Creator's RSA public key in PEM format (for signature verification)
 * @param verifySignature - Whether to verify signature (default: true, set false to skip)
 * @returns Decrypted capsa data
 * @throws Error if signature invalid, party not in keychain, or decryption fails
 */
export function decryptCapsa(
  capsa: Capsa,
  privateKey: string,
  partyId?: string,
  creatorPublicKey?: string,
  verifySignature = true
): DecryptedCapsa {
  // SECURITY: Verify capsa signature before decrypting
  if (verifySignature) {
    if (!creatorPublicKey) {
      throw new Error(
        'creatorPublicKey is required for signature verification. Pass verifySignature=false to skip (not recommended).'
      );
    }

    // SECURITY VALIDATION: Verify signature object exists with required fields
    if (!capsa.signature || typeof capsa.signature !== 'object' || !capsa.signature.signature) {
      throw new Error(
        `Capsa signature is missing or invalid (capsa: ${capsa.id}). Capsa may be corrupted or created with an old SDK version.`
      );
    }

    // Validate signature format (RSA-SHA256 produces 512-byte signature, base64url-encoded)
    try {
      const signatureBuffer = Buffer.from(capsa.signature.signature, 'base64url');
      if (signatureBuffer.length !== 512) {
        throw new Error(
          `Signature length validation failed: expected 512 bytes (RSA-4096-SHA256), got ${signatureBuffer.length} bytes (capsa: ${capsa.id}). Possible data corruption.`
        );
      }
    } catch (error) {
      if (error instanceof Error && error.message.includes('Signature length validation')) {
        throw error;
      }
      throw new Error(
        `Signature format validation failed: invalid base64url encoding (capsa: ${capsa.id}).`
      );
    }

    if (!creatorPublicKey.includes('BEGIN') || !creatorPublicKey.includes('PUBLIC KEY')) {
      throw new Error(
        `Creator public key format validation failed: missing PEM headers (creator: ${capsa.creator}).`
      );
    }

    // Build canonical string from capsa data (createdAt excluded - not part of signature)
    const canonicalString = buildCanonicalString({
      packageId: capsa.id,
      totalSize: capsa.totalSize,
      algorithm: capsa.keychain.algorithm,
      files: capsa.files,
      structuredIV: capsa.structuredIV,
      subjectIV: capsa.subjectIV,
      bodyIV: capsa.bodyIV,
    });

    const signatureValid = verifyCapsaSignature(
      capsa.signature,
      canonicalString,
      creatorPublicKey
    );

    if (!signatureValid) {
      throw new Error(
        `Signature verification failed: capsa data does not match signature (capsa: ${capsa.id}, creator: ${capsa.creator}). Capsa may have been tampered with or corrupted.`
      );
    }
  }

  let keychainEntry: KeychainEntry;

  if (partyId) {
    const foundEntry = findKeychainEntry(capsa, partyId);

    if (!foundEntry) {
      const delegateEntry = findDelegateEntry(capsa, partyId);
      if (!delegateEntry) {
        throw new Error(
          `Party ${partyId} not found in capsa keychain. Cannot decrypt.`
        );
      }
      keychainEntry = delegateEntry;
    } else {
      keychainEntry = foundEntry;
    }
  } else {
    // No partyId - use first keychain entry (API returns only authenticated party's key)
    if (!capsa.keychain.keys || capsa.keychain.keys.length === 0) {
      throw new Error('No keychain entries found in capsa. Cannot decrypt.');
    }

    const firstEntry = capsa.keychain.keys[0];
    if (!firstEntry) {
      throw new Error('First keychain entry is undefined. Cannot decrypt.');
    }
    keychainEntry = firstEntry;
  }

  if (!keychainEntry.encryptedKey) {
    const partyInfo = partyId || keychainEntry.party;
    throw new Error(
      `Party ${partyInfo} has no encrypted key in keychain. This party may be a delegated recipient without direct access.`
    );
  }

  // SECURITY VALIDATION: Verify encrypted key format and integrity
  // RSA-4096-OAEP outputs exactly 512 bytes, base64url-encoded
  const encryptedKeyBuffer = Buffer.from(keychainEntry.encryptedKey, 'base64url');
  if (encryptedKeyBuffer.length !== 512) {
    throw new Error(
      `Encrypted key length validation failed: expected 512 bytes (RSA-4096), got ${encryptedKeyBuffer.length} bytes (capsa: ${capsa.id}, party: ${partyId || keychainEntry.party}). Possible data corruption.`
    );
  }

  if (!privateKey || typeof privateKey !== 'string') {
    throw new Error('Private key is invalid or missing');
  }

  if (!privateKey.includes('BEGIN') || !privateKey.includes('PRIVATE KEY')) {
    throw new Error(
      `Private key format validation failed: missing PEM headers. Key may be corrupted.`
    );
  }

  let masterKey: Buffer;
  try {
    masterKey = decryptMasterKey(keychainEntry.encryptedKey, privateKey);
  } catch (error) {
    // Preserve original error details for diagnostics
    const originalMessage = error instanceof Error ? error.message : String(error);
    throw new Error(
      `RSA master key decryption failed: ${originalMessage} (capsa: ${capsa.id}, party: ${partyId || keychainEntry.party}, encryptedKeyLength: ${encryptedKeyBuffer.length})`
    );
  }

  // SECURITY VALIDATION: Verify decrypted master key is correct size
  // AES-256 requires exactly 32 bytes
  if (masterKey.length !== 32) {
    throw new Error(
      `Master key size validation failed: expected 32 bytes (AES-256), got ${masterKey.length} bytes. RSA decryption may have succeeded with wrong key.`
    );
  }

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

  // Map soft_deleted to expired for SDK consumers (soft_deleted is internal server status)
  const status: 'active' | 'expired' =
    capsa.status === 'soft_deleted' ? 'expired' :
    capsa.status === 'expired' ? 'expired' : 'active';

  const decryptedCapsa: DecryptedCapsa = {
    id: capsa.id,
    creator: capsa.creator,
    createdAt: capsa.createdAt,
    updatedAt: capsa.updatedAt,
    status,
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
      // Implementation added below
    }
  };

  // Non-enumerable to prevent serialization
  Object.defineProperty(decryptedCapsa, '_masterKey', {
    value: masterKey,
    enumerable: false,   // Hidden from enumeration
    writable: false,     // Immutable
    configurable: true   // Allow clearMasterKey() to replace with zeroed buffer
  });

  decryptedCapsa.clearMasterKey = function() {
    if (this._masterKey && this._masterKey.length > 0) {
      // Overwrite master key buffer with cryptographically random data
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

/**
 * Decrypt a file from a capsa
 *
 * SECURITY: Requires non-empty authTag for AES-GCM integrity verification
 *
 * @param encryptedFileData - Encrypted file data (base64url)
 * @param masterKey - Decrypted master key
 * @param iv - Initialization vector for file
 * @param authTag - Authentication tag for file (REQUIRED)
 * @returns Decrypted file buffer
 * @throws Error if authTag is missing or decryption fails
 */
export async function decryptFile(
  encryptedFileData: string,
  masterKey: Buffer,
  iv: string,
  authTag: string,
  compressed?: boolean
): Promise<Buffer> {
  // SECURITY: Validate authTag is present
  if (!authTag || authTag.trim() === '') {
    throw new Error(
      'SECURITY ERROR: authTag is required for file decryption. Missing authTag indicates potential tampering.'
    );
  }

  try {
    const decryptedData = decryptAES(encryptedFileData, masterKey, iv, authTag);

    if (compressed) {
      return await decompressData(decryptedData);
    }

    return decryptedData;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Failed to decrypt file: ${message}`);
  }
}

/**
 * Decrypt filename from capsa
 *
 * SECURITY: Requires non-empty authTag for AES-GCM integrity verification
 *
 * @param encryptedFilename - Encrypted filename (base64url)
 * @param masterKey - Decrypted master key
 * @param iv - Initialization vector for filename
 * @param authTag - Authentication tag for filename (REQUIRED)
 * @returns Decrypted filename
 * @throws Error if authTag is missing or decryption fails
 */
export function decryptFilename(
  encryptedFilename: string,
  masterKey: Buffer,
  iv: string,
  authTag: string
): string {
  // SECURITY: Validate authTag is present
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
    throw new Error(`Failed to decrypt filename: ${message}`);
  }
}
