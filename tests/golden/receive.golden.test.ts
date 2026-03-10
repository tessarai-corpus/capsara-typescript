/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Receive (Decryptor)
 * Tests wrong private key, party not in keychain, delegated recipient no key,
 * auto-detect party, signature length validation, encrypted key length,
 * master key size, masterKey non-enumerable. Tests decryptor directly.
 */

import * as crypto from 'crypto';
import { decryptCapsa, type DecryptedCapsa } from '../../src/internal/decryptor/capsa-decryptor.js';
import {
  generateMasterKey,
  encryptAES,
  encryptMasterKeyForParty,
} from '../../src/internal/crypto/primitives.js';
import { buildCanonicalString, createCapsaSignature } from '../../src/internal/crypto/signatures.js';
import type { Capsa } from '../../src/types/index.js';

function generateTestKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

function createFingerprint(publicKey: string): string {
  return crypto.createHash('sha256').update(publicKey).digest('hex');
}

let creatorKeys: { publicKey: string; privateKey: string };
let recipientKeys: { publicKey: string; privateKey: string };
let wrongKeys: { publicKey: string; privateKey: string };

beforeAll(() => {
  creatorKeys = generateTestKeyPair();
  recipientKeys = generateTestKeyPair();
  wrongKeys = generateTestKeyPair();
});

/**
 * Build a minimal valid encrypted capsa for testing
 */
function buildTestCapsa(options?: {
  recipientPublicKey?: string;
  recipientPartyId?: string;
  isDelegatedRecipient?: boolean;
  delegateId?: string;
  delegatePublicKey?: string;
  skipSignature?: boolean;
}): Capsa {
  const masterKey = generateMasterKey();
  const recipientPubKey = options?.recipientPublicKey ?? recipientKeys.publicKey;
  const recipientPartyId = options?.recipientPartyId ?? 'recipient_1';

  // Encrypt a test file
  const fileData = Buffer.from('test file content');
  const { encryptedData, iv: fileIV, authTag: fileAuthTag } = encryptAES(fileData, masterKey);
  const { encryptedData: encFilename, iv: filenameIV, authTag: filenameAuthTag } = encryptAES(
    Buffer.from('test.txt'),
    masterKey
  );
  const fileHash = crypto.createHash('sha256').update(Buffer.from(encryptedData, 'base64url')).digest('hex');

  const files = [{
    fileId: 'file_test.enc',
    encryptedFilename: encFilename,
    filenameIV,
    filenameAuthTag,
    iv: fileIV,
    authTag: fileAuthTag,
    mimetype: 'text/plain',
    size: Buffer.from(encryptedData, 'base64url').length,
    hash: fileHash,
    hashAlgorithm: 'SHA-256',
  }];

  const totalSize = files[0]!.size;

  // Build keychain
  const keychainKeys = [];

  // Creator entry
  keychainKeys.push({
    party: 'creator_1',
    encryptedKey: encryptMasterKeyForParty(masterKey, creatorKeys.publicKey),
    iv: crypto.randomBytes(12).toString('base64url'),
    fingerprint: createFingerprint(creatorKeys.publicKey),
    permissions: [] as string[],
    revoked: false,
  });

  if (options?.isDelegatedRecipient) {
    // Delegated recipient: no encrypted key
    keychainKeys.push({
      party: recipientPartyId,
      encryptedKey: '',
      iv: crypto.randomBytes(12).toString('base64url'),
      fingerprint: createFingerprint(recipientPubKey),
      permissions: [] as string[],
      revoked: false,
    });
    // Delegate with key
    if (options.delegateId && options.delegatePublicKey) {
      keychainKeys.push({
        party: options.delegateId,
        encryptedKey: encryptMasterKeyForParty(masterKey, options.delegatePublicKey),
        iv: crypto.randomBytes(12).toString('base64url'),
        fingerprint: createFingerprint(options.delegatePublicKey),
        permissions: ['delegate'],
        actingFor: [recipientPartyId],
        revoked: false,
      });
    }
  } else {
    // Standard recipient with encrypted key
    keychainKeys.push({
      party: recipientPartyId,
      encryptedKey: encryptMasterKeyForParty(masterKey, recipientPubKey),
      iv: crypto.randomBytes(12).toString('base64url'),
      fingerprint: createFingerprint(recipientPubKey),
      permissions: ['read'],
      revoked: false,
    });
  }

  // Build canonical string and signature
  const canonicalString = buildCanonicalString({
    packageId: 'capsa_test123',
    totalSize,
    algorithm: 'AES-256-GCM',
    files,
  });

  const signature = createCapsaSignature(canonicalString, creatorKeys.privateKey);

  return {
    id: 'capsa_test123',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    status: 'active',
    creator: 'creator_1',
    signature,
    keychain: { algorithm: 'AES-256-GCM', keys: keychainKeys },
    files,
    accessControl: {},
    totalSize,
  };
}

describe('Golden: Receive', () => {
  it('should decrypt capsa with correct private key', () => {
    const capsa = buildTestCapsa();
    const result = decryptCapsa(capsa, recipientKeys.privateKey, 'recipient_1', creatorKeys.publicKey);

    expect(result.id).toBe('capsa_test123');
    expect(result.status).toBe('active');
    expect(result.files).toHaveLength(1);
  });

  it('should throw with wrong private key', () => {
    const capsa = buildTestCapsa();

    expect(() =>
      decryptCapsa(capsa, wrongKeys.privateKey, 'recipient_1', creatorKeys.publicKey)
    ).toThrow(/RSA master key decryption failed/);
  });

  it('should throw when party not in keychain', () => {
    const capsa = buildTestCapsa();

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, 'unknown_party', creatorKeys.publicKey)
    ).toThrow(/not found in capsa keychain/);
  });

  it('should throw for delegated recipient with no encrypted key', () => {
    const capsa = buildTestCapsa({ isDelegatedRecipient: true });

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, 'recipient_1', creatorKeys.publicKey)
    ).toThrow(/no encrypted key/);
  });

  it('should auto-detect party from first keychain entry when partyId omitted', () => {
    const capsa = buildTestCapsa();
    // First entry is creator, which has an encrypted key
    const result = decryptCapsa(capsa, creatorKeys.privateKey, undefined, creatorKeys.publicKey);

    expect(result.id).toBe('capsa_test123');
  });

  it('should validate signature length is 512 bytes (RSA-4096-SHA256)', () => {
    const capsa = buildTestCapsa();
    // Tamper signature to wrong length
    capsa.signature.signature = Buffer.from('short-sig').toString('base64url');

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, 'recipient_1', creatorKeys.publicKey)
    ).toThrow(/Signature length validation failed/);
  });

  it('should validate encrypted key length is 512 bytes (RSA-4096)', () => {
    const capsa = buildTestCapsa();
    // Tamper encrypted key to wrong length
    const recipientEntry = capsa.keychain.keys.find(k => k.party === 'recipient_1');
    recipientEntry!.encryptedKey = Buffer.from('short').toString('base64url');

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, 'recipient_1', creatorKeys.publicKey)
    ).toThrow(/Encrypted key length validation failed/);
  });

  it('should validate decrypted master key is 32 bytes (AES-256)', () => {
    // This is tested implicitly since a correct RSA-4096-OAEP decryption of a
    // 32-byte master key always produces 32 bytes. A bad key produces an error.
    // We test that a successful decrypt has a 32-byte _masterKey.
    const capsa = buildTestCapsa();
    const result = decryptCapsa(capsa, recipientKeys.privateKey, 'recipient_1', creatorKeys.publicKey);

    expect(result._masterKey.length).toBe(32);
  });

  it('should make _masterKey non-enumerable', () => {
    const capsa = buildTestCapsa();
    const result = decryptCapsa(capsa, recipientKeys.privateKey, 'recipient_1', creatorKeys.publicKey);

    // Non-enumerable: not in Object.keys or JSON.stringify
    expect(Object.keys(result)).not.toContain('_masterKey');
    const json = JSON.stringify(result);
    expect(json).not.toContain('_masterKey');

    // But still accessible directly
    expect(result._masterKey).toBeDefined();
    expect(result._masterKey.length).toBe(32);
  });

  it('should require creatorPublicKey when verifySignature is true', () => {
    const capsa = buildTestCapsa();

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, 'recipient_1', undefined, true)
    ).toThrow(/creatorPublicKey is required/);
  });

  it('should skip signature verification when verifySignature is false', () => {
    const capsa = buildTestCapsa();
    // Tamper with signature - should not matter
    capsa.signature.signature = Buffer.from('x'.repeat(512)).toString('base64url');

    const result = decryptCapsa(
      capsa,
      recipientKeys.privateKey,
      'recipient_1',
      undefined,
      false // skip verification
    );

    expect(result.id).toBe('capsa_test123');
  });

  it('should provide clearMasterKey method for secure cleanup', () => {
    const capsa = buildTestCapsa();
    const result = decryptCapsa(capsa, recipientKeys.privateKey, 'recipient_1', creatorKeys.publicKey);

    expect(result._masterKey.length).toBe(32);

    result.clearMasterKey();

    expect(result._masterKey.length).toBe(0);
  });
});
