/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Receive (Decryptor)
 * Tests signer key binding (creatorPublicKey), private key selection by fingerprint,
 * party not in keychain, delegated recipient no key, signature length validation,
 * encrypted key length, master key size, masterKey non-enumerable. Tests decryptor directly.
 */

import * as crypto from 'crypto';
import { decryptCapsa } from '../../src/internal/decryptor/capsa-decryptor.js';
import {
  generateMasterKey,
  encryptAES,
  encryptMasterKeyForParty,
} from '../../src/internal/crypto/primitives.js';
import { buildCanonicalString, createCapsaSignature } from '../../src/internal/crypto/signatures.js';
import type { Capsa } from '../../src/types/index.js';
import { rsa4096KeyPair } from '../fixtures/rsa-keys.js';

function createFingerprint(publicKey: string): string {
  const der = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

const creatorKeys = rsa4096KeyPair(0);
const recipientKeys = rsa4096KeyPair(1);
const wrongKeys = rsa4096KeyPair(2);

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
  signedCreator?: string;
  signedKeyFingerprint?: string;
  legacyCanonical?: boolean;
  subjectIV?: string;
  bodyIV?: string;
  unlabelledIVs?: boolean;
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
    creatorPartyId: options?.signedCreator ?? 'creator_1',
    creatorKeyFingerprint: options?.signedKeyFingerprint ?? createFingerprint(creatorKeys.publicKey),
    files,
    ...(options?.subjectIV && { subjectIV: options.subjectIV }),
    ...(options?.bodyIV && { bodyIV: options.bodyIV }),
  });
  let signedString = options?.legacyCanonical
    ? canonicalString.split('|').filter((_part, i) => i !== 4 && i !== 5).join('|')
    : canonicalString;
  if (options?.unlabelledIVs) {
    signedString = signedString.replace('|subject:', '|').replace('|body:', '|');
  }

  const signature = createCapsaSignature(signedString, creatorKeys.privateKey);

  return {
    id: 'capsa_test123',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    status: 'active',
    creator: 'creator_1',
    creatorPublicKey: creatorKeys.publicKey,
    signature,
    keychain: { algorithm: 'AES-256-GCM', keys: keychainKeys },
    files,
    accessControl: {},
    totalSize,
    ...(options?.subjectIV && { subjectIV: options.subjectIV }),
    ...(options?.bodyIV && { bodyIV: options.bodyIV }),
  };
}

describe('Golden: Receive', () => {
  describe('signed creator binding', () => {
    it('should verify a capsa signed with the creator id and its key fingerprint', () => {
      expect(() => decryptCapsa(buildTestCapsa(), recipientKeys.privateKey, { partyId: 'recipient_1' })).not.toThrow();
    });

    it('should reject a capsa whose creator differs from the signed creator', () => {
      const capsa = { ...buildTestCapsa(), creator: 'impostor_1' };

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' }))
        .toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
    });

    it('should reject a capsa signed for a different creator id', () => {
      const capsa = buildTestCapsa({ signedCreator: 'someone_else' });

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' }))
        .toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
    });

    it('should reject a capsa signed with a different key fingerprint', () => {
      const capsa = buildTestCapsa({ signedKeyFingerprint: createFingerprint(wrongKeys.publicKey) });

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' }))
        .toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
    });

    it('should reject a creator public key that is really the private key PEM', () => {
      const capsa = { ...buildTestCapsa(), creatorPublicKey: creatorKeys.privateKey };

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' }))
        .toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED', statusCode: 0 }));
    });

    it('should reject a private-key creator public key when no creator entry is present', () => {
      const base = buildTestCapsa();
      const capsa = {
        ...base,
        creatorPublicKey: creatorKeys.privateKey,
        keychain: { ...base.keychain, keys: base.keychain.keys.filter((k) => k.party !== 'creator_1') },
      };

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' }))
        .toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
    });

    it('should reject a non-RSA creator public key as a verification failure, not a key mismatch', () => {
      const ecPem = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey
        .export({ type: 'spki', format: 'pem' }) as string;
      const capsa = { ...buildTestCapsa(), creatorPublicKey: ecPem };

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' }))
        .toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
    });

    it('should verify labelled subject and body IVs', () => {
      const capsa = buildTestCapsa({ subjectIV: 'subjectIV0001', bodyIV: 'bodyIV000002' });

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' })).not.toThrow();
    });

    it('should reject a capsa whose subject and body IVs were swapped', () => {
      const signed = buildTestCapsa({ subjectIV: 'subjectIV0001', bodyIV: 'bodyIV000002' });
      const capsa = { ...signed, subjectIV: signed.bodyIV, bodyIV: signed.subjectIV };

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' }))
        .toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
    });

    it('should reject a subject IV moved to the body', () => {
      const signed = buildTestCapsa({ subjectIV: 'subjectIV0001' });
      const { subjectIV, ...rest } = signed;
      const capsa = { ...rest, bodyIV: subjectIV };

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' }))
        .toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
    });

    it('should reject a signature over unlabelled optional IVs', () => {
      const capsa = buildTestCapsa({ subjectIV: 'subjectIV0001', bodyIV: 'bodyIV000002', unlabelledIVs: true });

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' }))
        .toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
    });

    it('should reject an old-format signature without the creator and key fingerprint', () => {
      const capsa = buildTestCapsa({ legacyCanonical: true });

      expect(() => decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' }))
        .toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
    });
  });

  it('should decrypt capsa with correct private key', () => {
    const capsa = buildTestCapsa();
    const result = decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' });

    expect(result.id).toBe('capsa_test123');
    expect(result.status).toBe('active');
    expect(result.files).toHaveLength(1);
  });

  it('should refuse a private key that does not match the keychain fingerprint', () => {
    const capsa = buildTestCapsa();

    expect(() =>
      decryptCapsa(capsa, wrongKeys.privateKey, { partyId: 'recipient_1' })
    ).toThrow(expect.objectContaining({ code: 'PRIVATE_KEY_NOT_AVAILABLE' }));
  });

  it('should decrypt with a previous private key after rotation', () => {
    const capsa = buildTestCapsa();
    const result = decryptCapsa(capsa, wrongKeys.privateKey, {
      partyId: 'recipient_1',
      previousPrivateKeys: [recipientKeys.privateKey],
    });

    expect(result._masterKey.length).toBe(32);
  });

  it('should throw when party not in keychain', () => {
    const capsa = buildTestCapsa();

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'unknown_party' })
    ).toThrow(expect.objectContaining({ code: 'NOT_IN_KEYCHAIN', statusCode: 0, details: { capsaId: capsa.id } }));
  });

  it('should throw for delegated recipient with no encrypted key', () => {
    const capsa = buildTestCapsa({ isDelegatedRecipient: true });

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' })
    ).toThrow(expect.objectContaining({ code: 'NO_ENCRYPTED_KEY', statusCode: 0, details: { capsaId: capsa.id } }));
  });

  it('should decrypt as the creator, checking the creator entry fingerprint', () => {
    const capsa = buildTestCapsa();
    const result = decryptCapsa(capsa, creatorKeys.privateKey, { partyId: 'creator_1' });

    expect(result.id).toBe('capsa_test123');
  });

  it('should use the only entry when partyId is omitted (API returns only the caller entry)', () => {
    const capsa = buildTestCapsa();
    capsa.keychain.keys = capsa.keychain.keys.filter(k => k.party === 'recipient_1');

    expect(decryptCapsa(capsa, recipientKeys.privateKey).id).toBe('capsa_test123');
  });

  it('should reject a creatorPublicKey that does not match the creator entry', () => {
    const capsa = buildTestCapsa();
    capsa.creatorPublicKey = wrongKeys.publicKey;

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' })
    ).toThrow(expect.objectContaining({ code: 'SIGNATURE_KEY_MISMATCH' }));
  });

  it('should reject a capsa without creatorPublicKey', () => {
    const capsa = buildTestCapsa();
    delete capsa.creatorPublicKey;

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' })
    ).toThrow(expect.objectContaining({ code: 'SIGNATURE_KEY_MISSING' }));
  });

  it('should reject a signature made by a different key', () => {
    const capsa = buildTestCapsa();
    // Recipients do not see the creator entry, so only the JWS check can catch this
    capsa.keychain.keys = capsa.keychain.keys.filter(k => k.party === 'recipient_1');
    capsa.creatorPublicKey = wrongKeys.publicKey;

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' })
    ).toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
  });

  it('should reject a capsa whose data no longer matches the signed payload', () => {
    const capsa = buildTestCapsa();
    capsa.totalSize += 1;

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' })
    ).toThrow(expect.objectContaining({ code: 'SIGNATURE_VERIFICATION_FAILED' }));
  });

  it('should validate signature length is 512 bytes (RSA-4096-SHA256)', () => {
    const capsa = buildTestCapsa();
    // Tamper signature to wrong length
    capsa.signature.signature = Buffer.from('short-sig').toString('base64url');

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' })
    ).toThrow(/expected a 512-byte signature/);
  });

  it('should validate encrypted key length is 512 bytes (RSA-4096)', () => {
    const capsa = buildTestCapsa();
    // Tamper encrypted key to wrong length
    const recipientEntry = capsa.keychain.keys.find(k => k.party === 'recipient_1');
    recipientEntry!.encryptedKey = Buffer.from('short').toString('base64url');

    expect(() =>
      decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' })
    ).toThrow(/Encrypted key length validation failed/);
  });

  it('should validate decrypted master key is 32 bytes (AES-256)', () => {
    // A correct RSA-4096-OAEP decryption of a 32-byte master key always produces
    // 32 bytes; a successful decrypt has a 32-byte _masterKey.
    const capsa = buildTestCapsa();
    const result = decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' });

    expect(result._masterKey.length).toBe(32);
  });

  it('should make _masterKey non-enumerable', () => {
    const capsa = buildTestCapsa();
    const result = decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' });

    // Non-enumerable: not in Object.keys or JSON.stringify
    expect(Object.keys(result)).not.toContain('_masterKey');
    const json = JSON.stringify(result);
    expect(json).not.toContain('_masterKey');

    // But still accessible directly
    expect(result._masterKey).toBeDefined();
    expect(result._masterKey.length).toBe(32);
  });

  it('should provide clearMasterKey method for secure cleanup', () => {
    const capsa = buildTestCapsa();
    const result = decryptCapsa(capsa, recipientKeys.privateKey, { partyId: 'recipient_1' });

    expect(result._masterKey.length).toBe(32);

    result.clearMasterKey();

    expect(result._masterKey.length).toBe(0);
  });
});
