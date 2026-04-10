/**
 * Tests for capsa-decryptor.ts - Capsa decryption utilities
 * @file tests/unit/internal/decryptor/capsa-decryptor.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import type { Capsa, KeychainEntry, EncryptedFile } from '../../../../src/types/index.js';
import { decryptCapsa, decryptFile, decryptFilename, type DecryptedCapsa } from '../../../../src/internal/decryptor/capsa-decryptor.js';

// Mock the crypto primitives and signatures modules
vi.mock('../../../../src/internal/crypto/primitives.js', () => ({
  decryptAES: vi.fn((encrypted: string, key: Buffer, iv: string, authTag: string) => {
    // Simple mock that returns decrypted content based on input
    if (encrypted === 'encrypted-subject') return Buffer.from('Decrypted Subject');
    if (encrypted === 'encrypted-body') return Buffer.from('Decrypted Body');
    if (encrypted === 'encrypted-structured') return Buffer.from('{"key":"value"}');
    if (encrypted === 'encrypted-file') return Buffer.from('Decrypted file content');
    if (encrypted === 'encrypted-filename') return Buffer.from('original-filename.txt');
    if (encrypted === 'bad-encrypted-data') throw new Error('Decryption failed');
    return Buffer.from('decrypted');
  }),
  decryptMasterKey: vi.fn((encryptedKey: string, privateKey: string) => {
    if (encryptedKey === 'bad-encrypted-key') throw new Error('RSA decryption failed');
    if (encryptedKey === 'wrong-size-key') return Buffer.alloc(16); // Wrong size
    // Return a valid 32-byte master key
    return Buffer.alloc(32, 0x42);
  }),
}));

vi.mock('../../../../src/internal/crypto/signatures.js', () => ({
  buildCanonicalString: vi.fn(() => 'canonical-string'),
  verifyCapsaSignature: vi.fn((signature, canonical, publicKey) => {
    // Return false if signature is 'invalid-signature'
    if (signature.signature === 'invalid-signature-value') return false;
    return true;
  }),
}));

vi.mock('../../../../src/internal/crypto/compression.js', () => ({
  decompressData: vi.fn((data: Buffer) => Promise.resolve(Buffer.from('decompressed-content'))),
}));

// Helper to create a valid 512-byte base64url encoded signature
function createValidSignature(): string {
  return Buffer.alloc(512, 0x41).toString('base64url');
}

// Helper to create a valid 512-byte base64url encoded key
function createValidEncryptedKey(): string {
  return Buffer.alloc(512, 0x42).toString('base64url');
}

// Helper to create a mock Capsa
function createMockCapsa(overrides?: Partial<Capsa>): Capsa {
  const defaultCapsa: Capsa = {
    id: 'capsa_123',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    status: 'active',
    creator: 'party_creator',
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
          fingerprint: 'ABC123',
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

// Helper to create a valid private key (PEM format)
function createMockPrivateKey(): string {
  return `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7+xWH8Y
-----END RSA PRIVATE KEY-----`;
}

// Helper to create a valid public key (PEM format)
function createMockPublicKey(): string {
  return `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcd
-----END PUBLIC KEY-----`;
}

describe('capsa-decryptor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('decryptCapsa', () => {
    describe('signature verification', () => {
      it('should verify signature by default when creatorPublicKey is provided', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();
        const publicKey = createMockPublicKey();

        const result = decryptCapsa(capsa, privateKey, 'party_123', publicKey);

        expect(result.id).toBe('capsa_123');
      });

      it('should throw when verifySignature=true but creatorPublicKey is missing', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', undefined, true)).toThrow(
          'creatorPublicKey is required for signature verification'
        );
      });

      it('should skip signature verification when verifySignature=false', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        // Should not throw even without public key
        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

        expect(result.id).toBe('capsa_123');
      });

      it('should throw when signature object is missing', () => {
        const capsa = createMockCapsa();
        (capsa as { signature: undefined }).signature = undefined as unknown as Capsa['signature'];
        const privateKey = createMockPrivateKey();
        const publicKey = createMockPublicKey();

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', publicKey)).toThrow(
          'Capsa signature is missing or invalid'
        );
      });

      it('should throw when signature.signature is missing', () => {
        const capsa = createMockCapsa();
        capsa.signature.signature = '';
        const privateKey = createMockPrivateKey();
        const publicKey = createMockPublicKey();

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', publicKey)).toThrow(
          'Capsa signature is missing or invalid'
        );
      });

      it('should throw when signature length is wrong', () => {
        const capsa = createMockCapsa();
        capsa.signature.signature = Buffer.alloc(256).toString('base64url'); // Wrong size
        const privateKey = createMockPrivateKey();
        const publicKey = createMockPublicKey();

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', publicKey)).toThrow(
          'Signature length validation failed'
        );
      });

      it('should throw when signature is invalid base64url', () => {
        const capsa = createMockCapsa();
        capsa.signature.signature = '!!!invalid-base64!!!';
        const privateKey = createMockPrivateKey();
        const publicKey = createMockPublicKey();

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', publicKey)).toThrow(
          /Signature.*validation failed/
        );
      });

      it('should throw when public key format is invalid', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();
        const invalidPublicKey = 'not-a-valid-pem-key';

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', invalidPublicKey)).toThrow(
          'Creator public key format validation failed'
        );
      });

      it('should throw when signature verification fails', async () => {
        const { verifyCapsaSignature } = await import('../../../../src/internal/crypto/signatures.js');
        (verifyCapsaSignature as ReturnType<typeof vi.fn>).mockReturnValueOnce(false);

        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();
        const publicKey = createMockPublicKey();

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', publicKey)).toThrow(
          'Signature verification failed'
        );
      });
    });

    describe('keychain entry lookup', () => {
      it('should find keychain entry by party ID', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

        expect(result.id).toBe('capsa_123');
      });

      it('should use first keychain entry when no partyId provided', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, undefined, undefined, false);

        expect(result.id).toBe('capsa_123');
      });

      it('should throw when party not found in keychain', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, 'unknown_party', undefined, false)).toThrow(
          'Party unknown_party not found in capsa keychain'
        );
      });

      it('should find delegate entry when party is acting as delegate', () => {
        const capsa = createMockCapsa({
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [
              {
                party: 'delegate_123',
                encryptedKey: createValidEncryptedKey(),
                iv: 'test-iv',
                fingerprint: 'DEF456',
                permissions: ['read'],
                actingFor: ['recipient_123'],
              },
            ],
          },
        });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, 'recipient_123', undefined, false);

        expect(result.id).toBe('capsa_123');
      });

      it('should throw when keychain is empty', () => {
        const capsa = createMockCapsa({
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [],
          },
        });
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, undefined, undefined, false)).toThrow(
          'No keychain entries found in capsa'
        );
      });

      it('should throw when keychain entry has no encrypted key (delegated recipient)', () => {
        const capsa = createMockCapsa({
          keychain: {
            algorithm: 'RSA-OAEP-SHA256',
            keys: [
              {
                party: 'recipient_123',
                encryptedKey: '', // No encrypted key
                iv: 'test-iv',
                fingerprint: 'ABC123',
                permissions: ['read'],
              },
            ],
          },
        });
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, 'recipient_123', undefined, false)).toThrow(
          'has no encrypted key in keychain'
        );
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

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', undefined, false)).toThrow(
          'Encrypted key length validation failed'
        );
      });

      it('should throw when private key is missing', () => {
        const capsa = createMockCapsa();

        expect(() => decryptCapsa(capsa, '', 'party_123', undefined, false)).toThrow(
          'Private key is invalid or missing'
        );
      });

      it('should throw when private key format is invalid', () => {
        const capsa = createMockCapsa();

        expect(() => decryptCapsa(capsa, 'not-a-valid-key', 'party_123', undefined, false)).toThrow(
          'Private key format validation failed'
        );
      });

      it('should throw when RSA decryption fails', async () => {
        const { decryptMasterKey } = await import('../../../../src/internal/crypto/primitives.js');
        (decryptMasterKey as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
          throw new Error('RSA decryption error');
        });

        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', undefined, false)).toThrow(
          'RSA master key decryption failed'
        );
      });

      it('should throw when decrypted master key has wrong size', async () => {
        const { decryptMasterKey } = await import('../../../../src/internal/crypto/primitives.js');
        (decryptMasterKey as ReturnType<typeof vi.fn>).mockReturnValueOnce(Buffer.alloc(16)); // Wrong size

        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', undefined, false)).toThrow(
          'Master key size validation failed'
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

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

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

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

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

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

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

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

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

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

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

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

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

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', undefined, false))
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

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', undefined, false))
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

        expect(() => decryptCapsa(capsa, privateKey, 'party_123', undefined, false))
          .toThrow('Structured decryption failed');
      });
    });

    describe('status mapping', () => {
      it('should map active status correctly', () => {
        const capsa = createMockCapsa({ status: 'active' });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

        expect(result.status).toBe('active');
      });

      it('should map soft_deleted to expired', () => {
        const capsa = createMockCapsa({ status: 'soft_deleted' });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

        expect(result.status).toBe('expired');
      });

      it('should map expired status correctly', () => {
        const capsa = createMockCapsa({ status: 'expired' });
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

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

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

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

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

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

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

        const originalKey = Buffer.from(result._masterKey);
        expect(result._masterKey.length).toBe(32);

        result.clearMasterKey();

        // After clearing, key should be empty
        expect(result._masterKey.length).toBe(0);
      });

      it('should handle clearMasterKey when already cleared', () => {
        const capsa = createMockCapsa();
        const privateKey = createMockPrivateKey();

        const result = decryptCapsa(capsa, privateKey, 'party_123', undefined, false);

        result.clearMasterKey();
        // Should not throw when called again
        expect(() => result.clearMasterKey()).not.toThrow();
      });
    });
  });

  describe('decryptFile', () => {
    it('should decrypt file with valid inputs', async () => {
      const masterKey = Buffer.alloc(32, 0x42);

      const result = await decryptFile('encrypted-file', masterKey, 'file-iv', 'file-auth-tag');

      expect(result.toString()).toBe('Decrypted file content');
    });

    it('should throw when authTag is missing', async () => {
      const masterKey = Buffer.alloc(32, 0x42);

      await expect(decryptFile('encrypted', masterKey, 'iv', '')).rejects.toThrow(
        'SECURITY ERROR: authTag is required'
      );
    });

    it('should throw when authTag is whitespace only', async () => {
      const masterKey = Buffer.alloc(32, 0x42);

      await expect(decryptFile('encrypted', masterKey, 'iv', '   ')).rejects.toThrow(
        'SECURITY ERROR: authTag is required'
      );
    });

    it('should decompress when compressed flag is true', async () => {
      const masterKey = Buffer.alloc(32, 0x42);

      const result = await decryptFile('encrypted-file', masterKey, 'iv', 'tag', true);

      expect(result.toString()).toBe('decompressed-content');
    });

    it('should not decompress when compressed flag is false', async () => {
      const masterKey = Buffer.alloc(32, 0x42);

      const result = await decryptFile('encrypted-file', masterKey, 'iv', 'tag', false);

      expect(result.toString()).toBe('Decrypted file content');
    });

    it('should wrap decryption errors', async () => {
      const { decryptAES } = await import('../../../../src/internal/crypto/primitives.js');
      (decryptAES as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
        throw new Error('AES decryption failed');
      });

      const masterKey = Buffer.alloc(32, 0x42);

      await expect(decryptFile('bad', masterKey, 'iv', 'tag')).rejects.toThrow(
        'Failed to decrypt file: AES decryption failed'
      );
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

      const result = decryptCapsa(capsa, privateKey, undefined, undefined, false);

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
