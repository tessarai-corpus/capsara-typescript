/**
 * Tests for capsa-decryptor.ts - Capsa decryption utilities
 * @file tests/unit/internal/decryptor/capsa-decryptor.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import type { Capsa, KeychainEntry, EncryptedFile } from '../../../../src/types/index.js';
import { CapsaraCapsaError } from '../../../../src/errors/capsa-error.js';
import { decryptCapsa, decryptFilename } from '../../../../src/internal/decryptor/capsa-decryptor.js';

// Mock the crypto primitives and signatures modules
vi.mock('../../../../src/internal/crypto/primitives.js', () => ({
  decryptAES: vi.fn((encrypted: string) => {
    // Simple mock that returns decrypted content based on input
    if (encrypted === 'encrypted-subject') return Buffer.from('Decrypted Subject');
    if (encrypted === 'encrypted-body') return Buffer.from('Decrypted Body');
    if (encrypted === 'encrypted-structured') return Buffer.from('{"key":"value"}');
    if (encrypted === 'encrypted-file') return Buffer.from('Decrypted file content');
    if (encrypted === 'encrypted-filename') return Buffer.from('original-filename.txt');
    if (encrypted === 'bad-encrypted-data') throw new Error('Decryption failed');
    return Buffer.from('decrypted');
  }),
  decryptMasterKey: vi.fn((encryptedKey: string) => {
    if (encryptedKey === 'bad-encrypted-key') throw new Error('RSA decryption failed');
    if (encryptedKey === 'wrong-size-key') return Buffer.alloc(16); // Wrong size
    // Return a valid 32-byte master key
    return Buffer.alloc(32, 0x42);
  }),
}));

vi.mock('../../../../src/internal/crypto/signatures.js', () => ({
  buildCanonicalString: vi.fn(() => 'canonical-string'),
  verifyCapsaSignature: vi.fn((signature: Capsa['signature']) => {
    // Return false if signature is 'invalid-signature'
    if (signature.signature === 'invalid-signature-value') return false;
    return true;
  }),
}));

vi.mock('../../../../src/internal/crypto/compression.js', () => ({
  decompressData: vi.fn(() => Promise.resolve(Buffer.from('decompressed-content'))),
}));

// Helper to create a valid 512-byte base64url encoded signature
function createValidSignature(): string {
  return Buffer.alloc(512, 0x41).toString('base64url');
}

// Helper to create a valid 512-byte base64url encoded key
function createValidEncryptedKey(): string {
  return Buffer.alloc(512, 0x42).toString('base64url');
}

// Real key pairs: the decryptor picks the private key by its public key fingerprint
function makeKeyPair(): { publicKey: string; privateKey: string } {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 1024,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function fingerprintOf(publicKeyPem: string): string {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

const recipientKeys = makeKeyPair();
const previousRecipientKeys = makeKeyPair();
const creatorKeys = makeKeyPair();
const RECIPIENT_FINGERPRINT = fingerprintOf(recipientKeys.publicKey);
const CREATOR_FINGERPRINT = fingerprintOf(creatorKeys.publicKey);

// Helper to create a mock Capsa
function createMockCapsa(overrides?: Partial<Capsa>): Capsa {
  const defaultCapsa: Capsa = {
    id: 'capsa_123',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    status: 'active',
    creator: 'party_creator',
    creatorPublicKey: creatorKeys.publicKey,
    signature: {
      algorithm: 'RSA-SHA256',
      protected: 'eyJ0eXAiOiJKV1QifQ',
      payload: 'eyJwYWNrYWdlSWQiOiJjYXBzYV8xMjMifQ',
      signature: createValidSignature(),
    },
    keychain: {
      algorithm: 'RSA-OAEP-SHA256',
      keys: [
        {
          party: 'party_123',
          encryptedKey: createValidEncryptedKey(),
          iv: 'test-iv',
          fingerprint: RECIPIENT_FINGERPRINT,
          permissions: ['read'],
        },
      ],
    },
    files: [],
    accessControl: {},
    totalSize: 1024,
  };

  return { ...defaultCapsa, ...overrides };
}

function entry(overrides: Partial<KeychainEntry>): KeychainEntry {
  return {
    party: 'party_123',
    encryptedKey: createValidEncryptedKey(),
    iv: 'test-iv',
    fingerprint: RECIPIENT_FINGERPRINT,
    permissions: ['read'],
    ...overrides,
  };
}

// The caller's current private key
function createMockPrivateKey(): string {
  return recipientKeys.privateKey;
}

function catchError(fn: () => unknown): CapsaraCapsaError {
  try {
    fn();
  } catch (error) {
    if (error instanceof CapsaraCapsaError) return error;
    throw error;
  }
  throw new Error('expected an error');
}

describe('capsa-decryptor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('decryptCapsa', () => {
    describe('signature verification (always on)', () => {
      it('verifies against creatorPublicKey and decrypts', async () => {
        const { verifyCapsaSignature } = await import('../../../../src/internal/crypto/signatures.js');
        const capsa = createMockCapsa();

        const result = decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' });

        expect(result.id).toBe('capsa_123');
        expect(verifyCapsaSignature).toHaveBeenCalledWith(capsa.signature, 'canonical-string', creatorKeys.publicKey);
      });

      it('rebuilds the signed string with the capsa creator and the DER fingerprint of creatorPublicKey', async () => {
        const { buildCanonicalString } = await import('../../../../src/internal/crypto/signatures.js');

        decryptCapsa(createMockCapsa(), createMockPrivateKey(), { partyId: 'party_123' });

        expect(buildCanonicalString).toHaveBeenCalledWith(expect.objectContaining({
          creatorPartyId: 'party_creator',
          creatorKeyFingerprint: fingerprintOf(creatorKeys.publicKey),
        }));
      });

      it('throws SIGNATURE_KEY_MISSING when creatorPublicKey is absent', () => {
        const capsa = createMockCapsa({ creatorPublicKey: undefined });

        const error = catchError(() => decryptCapsa(capsa, createMockPrivateKey()));

        expect(error.code).toBe('SIGNATURE_KEY_MISSING');
        expect(error.statusCode).toBe(0);
        expect(error.details).toEqual({ capsaId: 'capsa_123' });
      });

      it('throws SIGNATURE_KEY_MISSING when creatorPublicKey is empty', () => {
        expect(catchError(() => decryptCapsa(createMockCapsa({ creatorPublicKey: '' }), createMockPrivateKey())).code)
          .toBe('SIGNATURE_KEY_MISSING');
      });

      it('accepts a creator entry whose fingerprint matches creatorPublicKey', () => {
        const capsa = createMockCapsa({
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [entry({ party: 'party_creator', fingerprint: CREATOR_FINGERPRINT, permissions: [] }), entry({})],
          },
        });

        expect(decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' }).id).toBe('capsa_123');
      });

      it('throws SIGNATURE_KEY_MISMATCH when the creator entry fingerprint differs', () => {
        const capsa = createMockCapsa({
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [entry({ party: 'party_creator', fingerprint: 'f'.repeat(64) })],
          },
        });

        const error = catchError(() => decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_creator' }));

        expect(error.code).toBe('SIGNATURE_KEY_MISMATCH');
        expect(error.details).toEqual({ capsaId: 'capsa_123', expected: 'f'.repeat(64), actual: CREATOR_FINGERPRINT });
      });

      it('throws SIGNATURE_VERIFICATION_FAILED when creatorPublicKey cannot be parsed for the fingerprint check', () => {
        const capsa = createMockCapsa({
          creatorPublicKey: '-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----',
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [entry({ party: 'party_creator', fingerprint: CREATOR_FINGERPRINT })],
          },
        });

        const error = catchError(() => decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_creator' }));

        expect(error.code).toBe('SIGNATURE_VERIFICATION_FAILED');
        expect(error.message).toContain('cannot be parsed');
      });

      it('compares creator fingerprints independent of PEM layout', () => {
        const capsa = createMockCapsa({
          creatorPublicKey: creatorKeys.publicKey.replace(/\n/g, '\r\n'),
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [entry({ party: 'party_creator', fingerprint: CREATOR_FINGERPRINT, permissions: [] }), entry({})],
          },
        });

        expect(decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' }).id).toBe('capsa_123');
      });

      it('skips the fingerprint check when the creator entry is not in the response', () => {
        // Recipients only see their own entry
        const capsa = createMockCapsa({ creatorPublicKey: makeKeyPair().publicKey });

        expect(decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' }).id).toBe('capsa_123');
      });

      it('skips the fingerprint check when the creator entry has no fingerprint', () => {
        const capsa = createMockCapsa({
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [entry({ party: 'party_creator', fingerprint: '' }), entry({})],
          },
        });

        expect(decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' }).id).toBe('capsa_123');
      });

      it('throws SIGNATURE_VERIFICATION_FAILED when the signature object is missing', () => {
        const capsa = createMockCapsa({ signature: undefined as unknown as Capsa['signature'] });

        const error = catchError(() => decryptCapsa(capsa, createMockPrivateKey()));

        expect(error.code).toBe('SIGNATURE_VERIFICATION_FAILED');
        expect(error.statusCode).toBe(0);
        expect(error.message).toContain('signature is missing');
      });

      it('throws SIGNATURE_VERIFICATION_FAILED when signature.signature is empty', () => {
        const capsa = createMockCapsa({
          signature: { algorithm: 'RS256', protected: 'p', payload: 'q', signature: '' },
        });

        expect(catchError(() => decryptCapsa(capsa, createMockPrivateKey())).code).toBe('SIGNATURE_VERIFICATION_FAILED');
      });

      it('throws SIGNATURE_VERIFICATION_FAILED when the signature is not 512 bytes', () => {
        const capsa = createMockCapsa({
          signature: { algorithm: 'RS256', protected: 'p', payload: 'q', signature: Buffer.alloc(256).toString('base64url') },
        });

        const error = catchError(() => decryptCapsa(capsa, createMockPrivateKey()));

        expect(error.code).toBe('SIGNATURE_VERIFICATION_FAILED');
        expect(error.message).toContain('got 256 bytes');
      });

      it('throws SIGNATURE_VERIFICATION_FAILED when the payload does not bind to this capsa', async () => {
        const { verifyCapsaSignature } = await import('../../../../src/internal/crypto/signatures.js');
        (verifyCapsaSignature as ReturnType<typeof vi.fn>).mockReturnValueOnce(false);

        const error = catchError(() => decryptCapsa(createMockCapsa(), createMockPrivateKey()));

        expect(error.code).toBe('SIGNATURE_VERIFICATION_FAILED');
        expect(error.message).toContain('does not match the signature');
      });

      it('throws SIGNATURE_VERIFICATION_FAILED when verification throws (bad key, bad canonical data)', async () => {
        const { buildCanonicalString } = await import('../../../../src/internal/crypto/signatures.js');
        (buildCanonicalString as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
          throw new Error('File at index 0 missing required field: hash');
        });

        const error = catchError(() => decryptCapsa(createMockCapsa(), createMockPrivateKey()));

        expect(error.code).toBe('SIGNATURE_VERIFICATION_FAILED');
        expect(error.message).toContain('missing required field: hash');
      });

      it('wraps a non-Error thrown during verification', async () => {
        const { verifyCapsaSignature } = await import('../../../../src/internal/crypto/signatures.js');
        (verifyCapsaSignature as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
          throw 'odd';
        });

        expect(catchError(() => decryptCapsa(createMockCapsa(), createMockPrivateKey())).message).toContain('odd');
      });

      it('verifies before looking at the keychain', async () => {
        const { decryptMasterKey } = await import('../../../../src/internal/crypto/primitives.js');
        const capsa = createMockCapsa({ creatorPublicKey: undefined });

        expect(() => decryptCapsa(capsa, createMockPrivateKey())).toThrow();
        expect(decryptMasterKey).not.toHaveBeenCalled();
      });
    });

    describe('keychain entry lookup', () => {
      it('finds the keychain entry by party ID', () => {
        const capsa = createMockCapsa({
          keychain: { algorithm: 'RSA-OAEP-SHA256', keys: [entry({ party: 'party_other', fingerprint: 'x' }), entry({})] },
        });

        expect(decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' }).id).toBe('capsa_123');
      });

      it('uses the only entry when no party ID is given', () => {
        expect(decryptCapsa(createMockCapsa(), createMockPrivateKey()).id).toBe('capsa_123');
      });

      it('refuses to guess between several entries when no party ID is given', () => {
        const capsa = createMockCapsa({
          keychain: { algorithm: 'RSA-OAEP-SHA256', keys: [entry({ party: 'a' }), entry({ party: 'b' })] },
        });

        expect(() => decryptCapsa(capsa, createMockPrivateKey())).toThrow("Cannot pick the caller's entry");
        expect(() => decryptCapsa(capsa, createMockPrivateKey())).toThrow(
          expect.objectContaining({ code: 'PRIVATE_KEY_NOT_AVAILABLE', details: { capsaId: 'capsa_123', fingerprint: null } })
        );
      });

      it('throws NOT_IN_KEYCHAIN when the party is not in the keychain', () => {
        expect(() => decryptCapsa(createMockCapsa(), createMockPrivateKey(), { partyId: 'party_nobody' }))
          .toThrow('Party party_nobody not found in capsa keychain');
        expect(() => decryptCapsa(createMockCapsa(), createMockPrivateKey(), { partyId: 'party_nobody' })).toThrow(
          expect.objectContaining({ name: 'CapsaraCapsaError', code: 'NOT_IN_KEYCHAIN', statusCode: 0, details: { capsaId: 'capsa_123' } })
        );
      });

      it('finds the delegate entry acting for the party', () => {
        const capsa = createMockCapsa({
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [entry({ party: 'party_delegate', permissions: ['delegate'], actingFor: ['party_principal'] })],
          },
        });

        expect(decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_principal' }).id).toBe('capsa_123');
      });

      const notInKeychain = expect.objectContaining({
        name: 'CapsaraCapsaError', code: 'NOT_IN_KEYCHAIN', statusCode: 0, details: { capsaId: 'capsa_123' },
      });
      const noEncryptedKey = expect.objectContaining({
        name: 'CapsaraCapsaError', code: 'NO_ENCRYPTED_KEY', statusCode: 0, details: { capsaId: 'capsa_123' },
      });

      it('throws NOT_IN_KEYCHAIN when the keychain is empty', () => {
        const capsa = createMockCapsa({ keychain: { algorithm: 'RSA-OAEP-SHA256', keys: [] } });

        expect(() => decryptCapsa(capsa, createMockPrivateKey())).toThrow(notInKeychain);
      });

      it('throws NOT_IN_KEYCHAIN when the keychain is empty and a party id is given', () => {
        const capsa = createMockCapsa({ keychain: { algorithm: 'RSA-OAEP-SHA256', keys: [] } });

        expect(() => decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' })).toThrow(notInKeychain);
      });

      it('throws NOT_IN_KEYCHAIN when the keychain is missing', () => {
        const capsa = createMockCapsa({ keychain: { algorithm: 'RSA-OAEP-SHA256' } as Capsa['keychain'] });

        expect(() => decryptCapsa(capsa, createMockPrivateKey())).toThrow(notInKeychain);
      });

      it('throws NO_ENCRYPTED_KEY when the entry has no encrypted key (delegated recipient)', () => {
        const capsa = createMockCapsa({
          keychain: { algorithm: 'RSA-OAEP-SHA256', keys: [entry({ encryptedKey: '', permissions: [] })] },
        });

        expect(() => decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' }))
          .toThrow('has no encrypted key in keychain');
        expect(() => decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' })).toThrow(noEncryptedKey);
      });

      it('throws NO_ENCRYPTED_KEY for the single entry when no party id is given', () => {
        const capsa = createMockCapsa({
          keychain: { algorithm: 'RSA-OAEP-SHA256', keys: [entry({ encryptedKey: undefined as unknown as string })] },
        });

        expect(() => decryptCapsa(capsa, createMockPrivateKey())).toThrow(noEncryptedKey);
      });

      it('checks the encrypted key before its length', () => {
        const capsa = createMockCapsa({
          keychain: { algorithm: 'RSA-OAEP-SHA256', keys: [entry({ encryptedKey: Buffer.alloc(256).toString('base64url') })] },
        });

        expect(() => decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' })).toThrow('expected 512 bytes');
        expect(() => decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' })).toThrow(
          expect.objectContaining({ name: 'CapsaraCapsaError', code: 'INVALID_ENCRYPTED_KEY', statusCode: 0, details: { capsaId: 'capsa_123' } })
        );
      });

      it('checks the encrypted key length before selecting a private key', () => {
        const capsa = createMockCapsa({
          keychain: { algorithm: 'RSA-OAEP-SHA256', keys: [entry({ encryptedKey: Buffer.alloc(256).toString('base64url'), fingerprint: undefined })] },
        });

        expect(() => decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' })).toThrow(
          expect.objectContaining({ code: 'INVALID_ENCRYPTED_KEY' })
        );
      });
    });

    describe('private key selection', () => {
      it('uses the current key when its fingerprint matches', async () => {
        const { decryptMasterKey } = await import('../../../../src/internal/crypto/primitives.js');

        decryptCapsa(createMockCapsa(), recipientKeys.privateKey, { previousPrivateKeys: [previousRecipientKeys.privateKey] });

        expect(decryptMasterKey).toHaveBeenCalledWith(expect.any(String), recipientKeys.privateKey);
      });

      it('uses a previous key when the capsa was encrypted to it', async () => {
        const { decryptMasterKey } = await import('../../../../src/internal/crypto/primitives.js');
        const capsa = createMockCapsa({
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [entry({ fingerprint: fingerprintOf(previousRecipientKeys.publicKey) })],
          },
        });

        decryptCapsa(capsa, recipientKeys.privateKey, { previousPrivateKeys: [previousRecipientKeys.privateKey] });

        expect(decryptMasterKey).toHaveBeenCalledTimes(1);
        expect(decryptMasterKey).toHaveBeenCalledWith(expect.any(String), previousRecipientKeys.privateKey);
      });

      it('throws PRIVATE_KEY_NOT_AVAILABLE when no key matches, without trying any', async () => {
        const { decryptMasterKey } = await import('../../../../src/internal/crypto/primitives.js');
        const unknown = 'a'.repeat(64);
        const capsa = createMockCapsa({
          keychain: { algorithm: 'RSA-OAEP-SHA256', keys: [entry({ fingerprint: unknown })] },
        });

        const error = catchError(() =>
          decryptCapsa(capsa, recipientKeys.privateKey, { previousPrivateKeys: [previousRecipientKeys.privateKey] })
        );

        expect(error.code).toBe('PRIVATE_KEY_NOT_AVAILABLE');
        expect(error.statusCode).toBe(0);
        expect(error.details).toEqual({ capsaId: 'capsa_123', fingerprint: unknown });
        expect(error.message).toContain('addPreviousPrivateKey');
        expect(decryptMasterKey).not.toHaveBeenCalled();
      });

      it('throws PRIVATE_KEY_NOT_AVAILABLE when the entry carries no fingerprint', () => {
        const capsa = createMockCapsa({
          keychain: { algorithm: 'RSA-OAEP-SHA256', keys: [entry({ fingerprint: undefined as unknown as string })] },
        });

        const error = catchError(() => decryptCapsa(capsa, recipientKeys.privateKey));

        expect(error.code).toBe('PRIVATE_KEY_NOT_AVAILABLE');
        expect(error.details).toEqual({ capsaId: 'capsa_123', fingerprint: null });
      });

      it('fails with INVALID_PRIVATE_KEY instead of skipping a key that does not parse', async () => {
        const { decryptMasterKey } = await import('../../../../src/internal/crypto/primitives.js');
        const capsa = createMockCapsa({
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [entry({ fingerprint: fingerprintOf(previousRecipientKeys.publicKey) })],
          },
        });

        expect(() =>
          decryptCapsa(capsa, recipientKeys.privateKey, {
            previousPrivateKeys: ['-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----', previousRecipientKeys.privateKey],
          })
        ).toThrow(expect.objectContaining({ code: 'INVALID_PRIVATE_KEY', statusCode: 0, details: { capsaId: 'capsa_123' } }));
        expect(decryptMasterKey).not.toHaveBeenCalled();
      });
    });

    describe('master key decryption', () => {
      it('should validate encrypted key length', () => {
        const capsa = createMockCapsa({
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [
              {
                party: 'party_123',
                encryptedKey: Buffer.alloc(256).toString('base64url'), // Wrong size
                iv: 'test-iv',
                fingerprint: 'ABC123',
                permissions: ['read'],
              },
            ],
          },
        });
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, { partyId: 'party_123' })).toThrow(
          'Encrypted key length validation failed'
        );
      });

      it('should throw when private key is missing', () => {
        const capsa = createMockCapsa();

        expect(() => decryptCapsa(capsa, '', { partyId: 'party_123' })).toThrow(
          expect.objectContaining({ name: 'CapsaraError', code: 'INVALID_PRIVATE_KEY', statusCode: 0, details: { capsaId: 'capsa_123' } })
        );
      });

      it('should throw when private key format is invalid', () => {
        const capsa = createMockCapsa();

        expect(() => decryptCapsa(capsa, 'not-a-valid-key', { partyId: 'party_123' })).toThrow(
          expect.objectContaining({ code: 'INVALID_PRIVATE_KEY', statusCode: 0 })
        );
      });

      it('should throw when RSA decryption fails', async () => {
        const { decryptMasterKey } = await import('../../../../src/internal/crypto/primitives.js');
        (decryptMasterKey as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
          throw new Error('RSA decryption error');
        });

        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, { partyId: 'party_123' })).toThrow(
          expect.objectContaining({
            name: 'CapsaraCapsaError',
            code: 'KEY_DECRYPTION_FAILED',
            statusCode: 0,
            details: { capsaId: 'capsa_123' },
            message: expect.stringContaining('RSA master key decryption failed'),
          })
        );
      });

      it('should throw when decrypted master key has wrong size', async () => {
        const { decryptMasterKey } = await import('../../../../src/internal/crypto/primitives.js');
        (decryptMasterKey as ReturnType<typeof vi.fn>).mockReturnValueOnce(Buffer.alloc(16)); // Wrong size

        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, { partyId: 'party_123' })).toThrow(
          expect.objectContaining({
            code: 'KEY_DECRYPTION_FAILED',
            statusCode: 0,
            details: { capsaId: 'capsa_123' },
            message: expect.stringContaining('Master key size validation failed'),
          })
        );
      });
    });

    describe('encrypted field decryption', () => {
      it('should decrypt subject when present', () => {
        const capsa = createMockCapsa({
          encryptedSubject: 'encrypted-subject',
          subjectIV: 'subject-iv',
          subjectAuthTag: 'subject-auth-tag',
        });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        expect(result.subject).toBe('Decrypted Subject');
      });

      it('should skip subject decryption when authTag is missing', () => {
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

        const capsa = createMockCapsa({
          encryptedSubject: 'encrypted-subject',
          subjectIV: 'subject-iv',
          // No subjectAuthTag
        });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        expect(result.subject).toBeUndefined();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('missing authTag'));

        warnSpy.mockRestore();
      });

      it('should decrypt body when present', () => {
        const capsa = createMockCapsa({
          encryptedBody: 'encrypted-body',
          bodyIV: 'body-iv',
          bodyAuthTag: 'body-auth-tag',
        });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        expect(result.body).toBe('Decrypted Body');
      });

      it('should skip body decryption when authTag is missing', () => {
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

        const capsa = createMockCapsa({
          encryptedBody: 'encrypted-body',
          bodyIV: 'body-iv',
          // No bodyAuthTag
        });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        expect(result.body).toBeUndefined();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('missing authTag'));

        warnSpy.mockRestore();
      });

      it('should decrypt structured data when present', () => {
        const capsa = createMockCapsa({
          encryptedStructured: 'encrypted-structured',
          structuredIV: 'structured-iv',
          structuredAuthTag: 'structured-auth-tag',
        });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        expect(result.structured).toEqual({ key: 'value' });
      });

      it('should skip structured decryption when authTag is missing', () => {
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

        const capsa = createMockCapsa({
          encryptedStructured: 'encrypted-structured',
          structuredIV: 'structured-iv',
          // No structuredAuthTag
        });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        expect(result.structured).toBeUndefined();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('missing authTag'));

        warnSpy.mockRestore();
      });

      it('should throw on subject decryption failure (tamper detection)', async () => {
        const { decryptAES } = await import('../../../../src/internal/crypto/primitives.js');
        (decryptAES as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
          throw new Error('Decryption failed');
        });

        const capsa = createMockCapsa({
          encryptedSubject: 'encrypted-subject',
          subjectIV: 'subject-iv',
          subjectAuthTag: 'subject-auth-tag',
        });
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, { partyId: 'party_123' }))
          .toThrow('Decryption failed');
      });

      it('should throw on body decryption failure (tamper detection)', async () => {
        const { decryptAES } = await import('../../../../src/internal/crypto/primitives.js');
        (decryptAES as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
          throw new Error('Body decryption failed');
        });

        const capsa = createMockCapsa({
          encryptedBody: 'encrypted-body',
          bodyIV: 'body-iv',
          bodyAuthTag: 'body-auth-tag',
        });
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, { partyId: 'party_123' }))
          .toThrow('Body decryption failed');
      });

      it('should throw on structured data decryption failure (tamper detection)', async () => {
        const { decryptAES } = await import('../../../../src/internal/crypto/primitives.js');
        (decryptAES as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
          throw new Error('Structured decryption failed');
        });

        const capsa = createMockCapsa({
          encryptedStructured: 'encrypted-structured',
          structuredIV: 'structured-iv',
          structuredAuthTag: 'structured-auth-tag',
        });
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, { partyId: 'party_123' }))
          .toThrow('Structured decryption failed');
      });

      const contentFailure = expect.objectContaining({
        name: 'CapsaraCapsaError',
        code: 'CONTENT_DECRYPTION_FAILED',
        statusCode: 0,
        details: { capsaId: 'capsa_123' },
      });

      it.each([
        ['subject', { encryptedSubject: 'encrypted-subject', subjectIV: 'iv', subjectAuthTag: 'tag' }],
        ['body', { encryptedBody: 'encrypted-body', bodyIV: 'iv', bodyAuthTag: 'tag' }],
        ['structured data', { encryptedStructured: 'encrypted-structured', structuredIV: 'iv', structuredAuthTag: 'tag' }],
      ])('reports a %s decryption failure as CONTENT_DECRYPTION_FAILED', async (_label, fields) => {
        const { decryptAES } = await import('../../../../src/internal/crypto/primitives.js');
        (decryptAES as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
          throw new Error('AES-GCM decryption failed');
        });

        expect(() => decryptCapsa(createMockCapsa(fields), createMockPrivateKey(), { partyId: 'party_123' }))
          .toThrow(contentFailure);
      });

      it('reports structured data that is not JSON as CONTENT_DECRYPTION_FAILED', async () => {
        const { decryptAES } = await import('../../../../src/internal/crypto/primitives.js');
        (decryptAES as ReturnType<typeof vi.fn>).mockImplementationOnce(() => Buffer.from('{not json'));

        expect(() => decryptCapsa(
          createMockCapsa({ encryptedStructured: 'encrypted-structured', structuredIV: 'iv', structuredAuthTag: 'tag' }),
          createMockPrivateKey(),
          { partyId: 'party_123' }
        )).toThrow(contentFailure);
      });

      it('zeroes the master key when content decryption fails', async () => {
        const { decryptAES, decryptMasterKey } = await import('../../../../src/internal/crypto/primitives.js');
        const masterKey = Buffer.alloc(32, 0x42);
        (decryptMasterKey as ReturnType<typeof vi.fn>).mockReturnValueOnce(masterKey);
        (decryptAES as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
          throw new Error('AES-GCM decryption failed');
        });

        expect(() => decryptCapsa(
          createMockCapsa({ encryptedSubject: 'encrypted-subject', subjectIV: 'iv', subjectAuthTag: 'tag' }),
          createMockPrivateKey(),
          { partyId: 'party_123' }
        )).toThrow(contentFailure);
        expect(masterKey).toEqual(Buffer.alloc(32, 0));
      });
    });

    describe('status mapping', () => {
      it('should map active status correctly', () => {
        const capsa = createMockCapsa({ status: 'active' });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        expect(result.status).toBe('active');
      });

      it('passes soft_deleted through unchanged', () => {
        const capsa = createMockCapsa({ status: 'soft_deleted' });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        expect(result.status).toBe('soft_deleted');
      });

      it('passes an unknown server status through unchanged', () => {
        const result = decryptCapsa(createMockCapsa({ status: 'archived' }), createMockPrivateKey(), { partyId: 'party_123' });

        expect(result.status).toBe('archived');
      });

      it('keeps a missing status undefined instead of defaulting to active', () => {
        const capsa = createMockCapsa();
        delete (capsa as { status?: unknown }).status;

        expect(decryptCapsa(capsa, createMockPrivateKey(), { partyId: 'party_123' }).status).toBeUndefined();
      });

      it('keeps a null status null', () => {
        const result = decryptCapsa(createMockCapsa({ status: null }), createMockPrivateKey(), { partyId: 'party_123' });

        expect(result.status).toBeNull();
      });

      it('should map expired status correctly', () => {
        const capsa = createMockCapsa({ status: 'expired' });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        expect(result.status).toBe('expired');
      });
    });

    describe('result object', () => {
      it('should include all expected fields', () => {
        const mockFiles: EncryptedFile[] = [
          {
            fileId: 'file_1',
            encryptedFilename: 'encrypted',
            filenameIV: 'iv',
            filenameAuthTag: 'tag',
            iv: 'file-iv',
            authTag: 'file-tag',
            mimetype: 'text/plain',
            size: 100,
            hash: 'abc123',
            hashAlgorithm: 'SHA-256',
          },
        ];

        const capsa = createMockCapsa({
          files: mockFiles,
          accessControl: { expiresAt: '2025-01-01T00:00:00Z' },
          metadata: { label: 'Test' },
        });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        expect(result.id).toBe('capsa_123');
        expect(result.creator).toBe('party_creator');
        expect(result.createdAt).toBe('2024-01-01T00:00:00Z');
        expect(result.updatedAt).toBe('2024-01-01T00:00:00Z');
        expect(result.files).toEqual(mockFiles);
        expect(result.accessControl).toEqual({ expiresAt: '2025-01-01T00:00:00Z' });
        expect(result.keychain.algorithm).toBe('RSA-OAEP-SHA256');
        expect(result.signature.algorithm).toBe('RSA-SHA256');
        expect(result.metadata).toEqual({ label: 'Test' });
        expect(result.stats.totalSize).toBe(1024);
        expect(result.stats.fileCount).toBe(1);
        expect(result._encrypted).toBe(capsa);
      });

      it('should have non-enumerable _masterKey', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        // _masterKey should exist but not be enumerable
        expect(result._masterKey).toBeDefined();
        expect(result._masterKey.length).toBe(32);
        expect(Object.keys(result)).not.toContain('_masterKey');

        // Should not appear in JSON
        const json = JSON.stringify(result);
        expect(json).not.toContain('_masterKey');
      });

      it('should have clearMasterKey method that zeros memory', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        const keyBuffer = result._masterKey;
        const originalKey = Buffer.from(keyBuffer);
        expect(result._masterKey.length).toBe(32);

        result.clearMasterKey();

        // After clearing, key should be empty
        expect(result._masterKey.length).toBe(0);
        // The original buffer was overwritten in place
        expect(keyBuffer.equals(originalKey)).toBe(false);
      });

      it('should handle clearMasterKey when already cleared', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, { partyId: 'party_123' });

        result.clearMasterKey();
        // Should not throw when called again
        expect(() => result.clearMasterKey()).not.toThrow();
      });
    });
  });

  describe('decryptFilename', () => {
    it('should decrypt filename with valid inputs', () => {
      const masterKey = Buffer.alloc(32, 0x42);

      const result = decryptFilename('encrypted-filename', masterKey, 'iv', 'tag');

      expect(result).toBe('original-filename.txt');
    });

    it('should throw when authTag is missing', () => {
      const masterKey = Buffer.alloc(32, 0x42);

      expect(() => decryptFilename('encrypted', masterKey, 'iv', '')).toThrow(
        'SECURITY ERROR: authTag is required'
      );
    });

    it('should throw when authTag is whitespace only', () => {
      const masterKey = Buffer.alloc(32, 0x42);

      expect(() => decryptFilename('encrypted', masterKey, 'iv', '   ')).toThrow(
        'SECURITY ERROR: authTag is required'
      );
    });

    it('should wrap decryption errors', async () => {
      const { decryptAES } = await import('../../../../src/internal/crypto/primitives.js');
      (decryptAES as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
        throw new Error('Decryption error');
      });

      const masterKey = Buffer.alloc(32, 0x42);

      expect(() => decryptFilename('bad', masterKey, 'iv', 'tag')).toThrow(
        'Failed to decrypt filename: Decryption error'
      );
    });
  });

  describe('DecryptedCapsa interface', () => {
    it('should have all required fields', () => {
      const capsa = createMockCapsa();
      const privateKey = createMockPrivateKey();

      const result = decryptCapsa(capsa, privateKey);

      // Required fields
      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('creator');
      expect(result).toHaveProperty('createdAt');
      expect(result).toHaveProperty('updatedAt');
      expect(result).toHaveProperty('status');
      expect(result).toHaveProperty('files');
      expect(result).toHaveProperty('accessControl');
      expect(result).toHaveProperty('keychain');
      expect(result).toHaveProperty('signature');
      expect(result).toHaveProperty('stats');
      expect(result).toHaveProperty('_encrypted');
      expect(result).toHaveProperty('clearMasterKey');

      // Stats fields
      expect(result.stats).toHaveProperty('totalSize');
      expect(result.stats).toHaveProperty('fileCount');
    });
  });
});
