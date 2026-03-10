/// <reference types="vitest/globals" />
/**
 * Tests for RSA key generation module
 * @module tests/unit/internal/crypto/key-generator.test
 *
 * Tests RSA-4096 key pair generation, fingerprint calculation, and key pair validation
 * with full branch coverage including edge cases and error scenarios.
 */

import * as crypto from 'crypto';
import {
  generateKeyPair,
  calculateKeyFingerprint,
  validateKeyPair,
  type GeneratedKeyPair,
} from '../../../../src/internal/crypto/key-generator.js';

/**
 * Pre-generated key pairs for tests to avoid expensive key generation in each test.
 * RSA-4096 key generation takes ~1-2 seconds, so we generate once and reuse.
 */
let validKeyPair: GeneratedKeyPair;
let secondValidKeyPair: GeneratedKeyPair;

beforeAll(async () => {
  // Generate key pairs once before all tests (expensive operation)
  validKeyPair = await generateKeyPair();
  secondValidKeyPair = await generateKeyPair();
});

describe('generateKeyPair', () => {
  describe('Return Value Structure', () => {
    it('should return an object with all required properties', () => {
      expect(validKeyPair).toHaveProperty('publicKey');
      expect(validKeyPair).toHaveProperty('privateKey');
      expect(validKeyPair).toHaveProperty('publicKeyFingerprint');
      expect(validKeyPair).toHaveProperty('algorithm');
      expect(validKeyPair).toHaveProperty('keySize');
      expect(validKeyPair).toHaveProperty('publicExponent');
    });

    it('should return string type for publicKey', () => {
      expect(typeof validKeyPair.publicKey).toBe('string');
    });

    it('should return string type for privateKey', () => {
      expect(typeof validKeyPair.privateKey).toBe('string');
    });

    it('should return string type for publicKeyFingerprint', () => {
      expect(typeof validKeyPair.publicKeyFingerprint).toBe('string');
    });
  });

  describe('Algorithm Metadata', () => {
    it('should have algorithm set to RSA-4096', () => {
      expect(validKeyPair.algorithm).toBe('RSA-4096');
    });

    it('should have keySize set to 4096', () => {
      expect(validKeyPair.keySize).toBe(4096);
    });

    it('should have publicExponent set to 65537', () => {
      expect(validKeyPair.publicExponent).toBe(65537);
    });
  });

  describe('Public Key Format', () => {
    it('should return public key in PEM format', () => {
      expect(validKeyPair.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(validKeyPair.publicKey).toContain('-----END PUBLIC KEY-----');
    });

    it('should have X.509 SubjectPublicKeyInfo format (spki)', () => {
      // X.509 SubjectPublicKeyInfo uses "PUBLIC KEY" marker (not "RSA PUBLIC KEY")
      expect(validKeyPair.publicKey).toMatch(/-----BEGIN PUBLIC KEY-----/);
      expect(validKeyPair.publicKey).not.toContain('RSA PUBLIC KEY');
    });

    it('should have valid base64 content between PEM markers', () => {
      const lines = validKeyPair.publicKey.split('\n');
      const contentLines = lines.slice(1, -2); // Skip header and footer
      const base64Content = contentLines.join('');

      // Base64 characters only (with possible whitespace)
      const base64Regex = /^[A-Za-z0-9+/=\s]*$/;
      expect(base64Regex.test(base64Content)).toBe(true);
    });

    it('should be parseable by Node.js crypto module', () => {
      const keyObject = crypto.createPublicKey(validKeyPair.publicKey);
      expect(keyObject.type).toBe('public');
      expect(keyObject.asymmetricKeyType).toBe('rsa');
    });

    it('should have correct modulus length (4096 bits)', () => {
      const keyObject = crypto.createPublicKey(validKeyPair.publicKey);
      const keyDetails = keyObject.asymmetricKeyDetails;
      expect(keyDetails?.modulusLength).toBe(4096);
    });

    it('should have correct public exponent (65537)', () => {
      const keyObject = crypto.createPublicKey(validKeyPair.publicKey);
      const keyDetails = keyObject.asymmetricKeyDetails;
      // publicExponent is stored as BigInt in Node.js
      expect(keyDetails?.publicExponent).toBe(65537n);
    });
  });

  describe('Private Key Format', () => {
    it('should return private key in PEM format', () => {
      expect(validKeyPair.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
      expect(validKeyPair.privateKey).toContain('-----END PRIVATE KEY-----');
    });

    it('should have PKCS#8 format (not PKCS#1)', () => {
      // PKCS#8 uses "PRIVATE KEY" marker (not "RSA PRIVATE KEY")
      expect(validKeyPair.privateKey).toMatch(/-----BEGIN PRIVATE KEY-----/);
      expect(validKeyPair.privateKey).not.toContain('RSA PRIVATE KEY');
    });

    it('should have valid base64 content between PEM markers', () => {
      const lines = validKeyPair.privateKey.split('\n');
      const contentLines = lines.slice(1, -2); // Skip header and footer
      const base64Content = contentLines.join('');

      const base64Regex = /^[A-Za-z0-9+/=\s]*$/;
      expect(base64Regex.test(base64Content)).toBe(true);
    });

    it('should be parseable by Node.js crypto module', () => {
      const keyObject = crypto.createPrivateKey(validKeyPair.privateKey);
      expect(keyObject.type).toBe('private');
      expect(keyObject.asymmetricKeyType).toBe('rsa');
    });

    it('should have correct modulus length (4096 bits)', () => {
      const keyObject = crypto.createPrivateKey(validKeyPair.privateKey);
      const keyDetails = keyObject.asymmetricKeyDetails;
      expect(keyDetails?.modulusLength).toBe(4096);
    });
  });

  describe('Fingerprint Format', () => {
    it('should return 64-character hex string (SHA-256)', () => {
      expect(validKeyPair.publicKeyFingerprint).toHaveLength(64);
    });

    it('should contain only lowercase hex characters', () => {
      const hexRegex = /^[a-f0-9]+$/;
      expect(hexRegex.test(validKeyPair.publicKeyFingerprint)).toBe(true);
    });

    it('should not contain uppercase hex characters', () => {
      expect(validKeyPair.publicKeyFingerprint).toBe(validKeyPair.publicKeyFingerprint.toLowerCase());
    });

    it('should match calculateKeyFingerprint output for same public key', () => {
      const recalculatedFingerprint = calculateKeyFingerprint(validKeyPair.publicKey);
      expect(validKeyPair.publicKeyFingerprint).toBe(recalculatedFingerprint);
    });
  });

  describe('Key Uniqueness', () => {
    it('should generate different public keys on each call', () => {
      expect(validKeyPair.publicKey).not.toBe(secondValidKeyPair.publicKey);
    });

    it('should generate different private keys on each call', () => {
      expect(validKeyPair.privateKey).not.toBe(secondValidKeyPair.privateKey);
    });

    it('should generate different fingerprints on each call', () => {
      expect(validKeyPair.publicKeyFingerprint).not.toBe(secondValidKeyPair.publicKeyFingerprint);
    });
  });

  describe('Encryption/Decryption Round-Trip', () => {
    it('should generate keys that can encrypt and decrypt data', () => {
      const testData = Buffer.from('Hello, Capsara SDK!');

      const encrypted = crypto.publicEncrypt(
        {
          key: validKeyPair.publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        testData
      );

      const decrypted = crypto.privateDecrypt(
        {
          key: validKeyPair.privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        encrypted
      );

      expect(decrypted.equals(testData)).toBe(true);
    });

    it('should generate keys that work with maximum payload size', () => {
      // RSA-4096-OAEP-SHA256 max payload: 4096/8 - 2*32 - 2 = 446 bytes
      const maxPayloadSize = 446;
      const testData = crypto.randomBytes(maxPayloadSize);

      const encrypted = crypto.publicEncrypt(
        {
          key: validKeyPair.publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        testData
      );

      const decrypted = crypto.privateDecrypt(
        {
          key: validKeyPair.privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        encrypted
      );

      expect(decrypted.equals(testData)).toBe(true);
    });

    it('should generate keys that produce 512-byte ciphertext', () => {
      const testData = Buffer.from('test');

      const encrypted = crypto.publicEncrypt(
        {
          key: validKeyPair.publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        testData
      );

      // RSA-4096 produces 512-byte (4096-bit) ciphertext
      expect(encrypted.length).toBe(512);
    });
  });

  describe('Digital Signature Round-Trip', () => {
    it('should generate keys that can sign and verify data', () => {
      const testData = Buffer.from('Data to be signed');

      const signature = crypto.sign('sha256', testData, {
        key: validKeyPair.privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      });

      const isValid = crypto.verify('sha256', testData, {
        key: validKeyPair.publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      }, signature);

      expect(isValid).toBe(true);
    });

    it('should produce 512-byte signatures with RSA-4096', () => {
      const testData = Buffer.from('Data to be signed');

      const signature = crypto.sign('sha256', testData, {
        key: validKeyPair.privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      });

      expect(signature.length).toBe(512);
    });
  });

  describe('Async Behavior', () => {
    it('should return a Promise', () => {
      const result = generateKeyPair();
      expect(result).toBeInstanceOf(Promise);
    });

    it('should resolve successfully', async () => {
      const result = await generateKeyPair();
      expect(result).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey).toBeDefined();
    });
  });
});

describe('calculateKeyFingerprint', () => {
  describe('Output Format', () => {
    it('should return a string', () => {
      const fingerprint = calculateKeyFingerprint(validKeyPair.publicKey);
      expect(typeof fingerprint).toBe('string');
    });

    it('should return exactly 64 characters (SHA-256 hex)', () => {
      const fingerprint = calculateKeyFingerprint(validKeyPair.publicKey);
      expect(fingerprint).toHaveLength(64);
    });

    it('should return lowercase hex only', () => {
      const fingerprint = calculateKeyFingerprint(validKeyPair.publicKey);
      const hexRegex = /^[a-f0-9]+$/;
      expect(hexRegex.test(fingerprint)).toBe(true);
    });

    it('should not contain uppercase characters', () => {
      const fingerprint = calculateKeyFingerprint(validKeyPair.publicKey);
      expect(fingerprint).toBe(fingerprint.toLowerCase());
      expect(fingerprint).not.toMatch(/[A-F]/);
    });
  });

  describe('Consistency', () => {
    it('should return same fingerprint for same input', () => {
      const fingerprint1 = calculateKeyFingerprint(validKeyPair.publicKey);
      const fingerprint2 = calculateKeyFingerprint(validKeyPair.publicKey);
      expect(fingerprint1).toBe(fingerprint2);
    });

    it('should return consistent results across multiple calls', () => {
      const fingerprints = new Set<string>();
      for (let i = 0; i < 10; i++) {
        fingerprints.add(calculateKeyFingerprint(validKeyPair.publicKey));
      }
      expect(fingerprints.size).toBe(1);
    });
  });

  describe('Uniqueness', () => {
    it('should return different fingerprint for different keys', () => {
      const fingerprint1 = calculateKeyFingerprint(validKeyPair.publicKey);
      const fingerprint2 = calculateKeyFingerprint(secondValidKeyPair.publicKey);
      expect(fingerprint1).not.toBe(fingerprint2);
    });

    it('should return different fingerprint for slightly modified input', () => {
      const original = calculateKeyFingerprint(validKeyPair.publicKey);
      // Modify the PEM content slightly
      const modifiedPEM = validKeyPair.publicKey.replace('A', 'B');
      const modified = calculateKeyFingerprint(modifiedPEM);
      expect(original).not.toBe(modified);
    });
  });

  describe('Known Hash Verification', () => {
    it('should produce known SHA-256 hash for known input', () => {
      // Known SHA-256 of "test"
      const testInput = 'test';
      const expectedHash = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
      const result = calculateKeyFingerprint(testInput);
      expect(result).toBe(expectedHash);
    });

    it('should produce known SHA-256 hash for empty string', () => {
      const expectedHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const result = calculateKeyFingerprint('');
      expect(result).toBe(expectedHash);
    });

    it('should produce known SHA-256 hash for hello', () => {
      const expectedHash = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
      const result = calculateKeyFingerprint('hello');
      expect(result).toBe(expectedHash);
    });
  });

  describe('PEM Content Handling', () => {
    it('should hash the entire PEM string including headers and footers', () => {
      // Create two PEMs with same key content but different formatting
      const pem = validKeyPair.publicKey;
      const trimmedPEM = pem.trim();

      // Both should produce same fingerprint if they're identical
      expect(calculateKeyFingerprint(pem)).toBe(calculateKeyFingerprint(pem));

      // If there's whitespace difference, fingerprint should differ
      const pemWithExtraNewline = pem + '\n';
      const fingerprintOriginal = calculateKeyFingerprint(pem);
      const fingerprintModified = calculateKeyFingerprint(pemWithExtraNewline);
      expect(fingerprintOriginal).not.toBe(fingerprintModified);
    });

    it('should produce different fingerprint for different PEM types', () => {
      // Even same key in different formats should have different fingerprints
      const spkiFingerprint = calculateKeyFingerprint(validKeyPair.publicKey);

      // Create PKCS#1 format of same key
      const keyObject = crypto.createPublicKey(validKeyPair.publicKey);
      const pkcs1PEM = keyObject.export({ type: 'pkcs1', format: 'pem' }) as string;
      const pkcs1Fingerprint = calculateKeyFingerprint(pkcs1PEM);

      expect(spkiFingerprint).not.toBe(pkcs1Fingerprint);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string input', () => {
      const fingerprint = calculateKeyFingerprint('');
      expect(fingerprint).toHaveLength(64);
    });

    it('should handle single character input', () => {
      const fingerprint = calculateKeyFingerprint('a');
      expect(fingerprint).toHaveLength(64);
    });

    it('should handle very long input', () => {
      const longInput = 'a'.repeat(10000);
      const fingerprint = calculateKeyFingerprint(longInput);
      expect(fingerprint).toHaveLength(64);
    });

    it('should handle unicode characters', () => {
      const unicodeInput = 'Hello \u4e16\u754c \u{1F600}';
      const fingerprint = calculateKeyFingerprint(unicodeInput);
      expect(fingerprint).toHaveLength(64);
    });

    it('should handle newlines and whitespace', () => {
      const inputWithWhitespace = '  \n\t  test  \n\t  ';
      const fingerprint = calculateKeyFingerprint(inputWithWhitespace);
      expect(fingerprint).toHaveLength(64);
    });

    it('should handle binary-like content in string', () => {
      const binaryContent = '\x00\x01\x02\x03\xff\xfe\xfd';
      const fingerprint = calculateKeyFingerprint(binaryContent);
      expect(fingerprint).toHaveLength(64);
    });
  });
});

describe('validateKeyPair', () => {
  describe('Valid Key Pairs', () => {
    it('should return true for matching key pair', () => {
      const result = validateKeyPair(validKeyPair.publicKey, validKeyPair.privateKey);
      expect(result).toBe(true);
    });

    it('should return true for second valid key pair', () => {
      const result = validateKeyPair(secondValidKeyPair.publicKey, secondValidKeyPair.privateKey);
      expect(result).toBe(true);
    });

    it('should return true for freshly generated key pair', async () => {
      const freshPair = await generateKeyPair();
      const result = validateKeyPair(freshPair.publicKey, freshPair.privateKey);
      expect(result).toBe(true);
    }, 15000); // RSA-4096 key generation is slow
  });

  describe('Mismatched Key Pairs', () => {
    it('should return false when public key is from different pair', () => {
      const result = validateKeyPair(secondValidKeyPair.publicKey, validKeyPair.privateKey);
      expect(result).toBe(false);
    });

    it('should return false when private key is from different pair', () => {
      const result = validateKeyPair(validKeyPair.publicKey, secondValidKeyPair.privateKey);
      expect(result).toBe(false);
    });

    it('should return false when both keys are from different pairs', () => {
      // Generate a third key pair to have completely unrelated keys
      const { publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const result = validateKeyPair(publicKey, validKeyPair.privateKey);
      expect(result).toBe(false);
    });
  });

  describe('Invalid PEM Format - Public Key', () => {
    it('should return false for public key without BEGIN PUBLIC KEY marker', () => {
      const invalidPublicKey = validKeyPair.publicKey.replace('BEGIN PUBLIC KEY', 'BEGIN INVALID');
      const result = validateKeyPair(invalidPublicKey, validKeyPair.privateKey);
      expect(result).toBe(false);
    });

    it('should return false for empty public key string', () => {
      const result = validateKeyPair('', validKeyPair.privateKey);
      expect(result).toBe(false);
    });

    it('should return false for public key with only markers but no content', () => {
      const emptyPEM = '-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----';
      const result = validateKeyPair(emptyPEM, validKeyPair.privateKey);
      expect(result).toBe(false);
    });

    it('should return false for public key with invalid base64 content', () => {
      const invalidPEM = '-----BEGIN PUBLIC KEY-----\n!!invalid!!base64!!\n-----END PUBLIC KEY-----';
      const result = validateKeyPair(invalidPEM, validKeyPair.privateKey);
      expect(result).toBe(false);
    });

    it('should return false for plain text instead of public key', () => {
      const result = validateKeyPair('not a pem key', validKeyPair.privateKey);
      expect(result).toBe(false);
    });

    it('should return false for RSA PUBLIC KEY format (PKCS#1) without proper content', () => {
      const pkcs1Format = '-----BEGIN RSA PUBLIC KEY-----\ninvalid\n-----END RSA PUBLIC KEY-----';
      const result = validateKeyPair(pkcs1Format, validKeyPair.privateKey);
      expect(result).toBe(false);
    });
  });

  describe('Invalid PEM Format - Private Key', () => {
    it('should return false for private key without BEGIN PRIVATE KEY marker', () => {
      const invalidPrivateKey = validKeyPair.privateKey.replace('BEGIN PRIVATE KEY', 'BEGIN INVALID');
      const result = validateKeyPair(validKeyPair.publicKey, invalidPrivateKey);
      expect(result).toBe(false);
    });

    it('should return false for empty private key string', () => {
      const result = validateKeyPair(validKeyPair.publicKey, '');
      expect(result).toBe(false);
    });

    it('should return false for private key with only markers but no content', () => {
      const emptyPEM = '-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----';
      const result = validateKeyPair(validKeyPair.publicKey, emptyPEM);
      expect(result).toBe(false);
    });

    it('should return false for private key with invalid base64 content', () => {
      const invalidPEM = '-----BEGIN PRIVATE KEY-----\n!!invalid!!base64!!\n-----END PRIVATE KEY-----';
      const result = validateKeyPair(validKeyPair.publicKey, invalidPEM);
      expect(result).toBe(false);
    });

    it('should return false for plain text instead of private key', () => {
      const result = validateKeyPair(validKeyPair.publicKey, 'not a pem key');
      expect(result).toBe(false);
    });

    it('should return false for RSA PRIVATE KEY format (PKCS#1) without proper content', () => {
      const pkcs1Format = '-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----';
      const result = validateKeyPair(validKeyPair.publicKey, pkcs1Format);
      expect(result).toBe(false);
    });
  });

  describe('Both Keys Invalid', () => {
    it('should return false when both keys are empty strings', () => {
      const result = validateKeyPair('', '');
      expect(result).toBe(false);
    });

    it('should return false when both keys are plain text', () => {
      const result = validateKeyPair('public key here', 'private key here');
      expect(result).toBe(false);
    });

    it('should return false when both keys have invalid PEM content', () => {
      const invalidPublic = '-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----';
      const invalidPrivate = '-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----';
      const result = validateKeyPair(invalidPublic, invalidPrivate);
      expect(result).toBe(false);
    });
  });

  describe('Wrong Key Types', () => {
    it('should return false for EC key pair (OAEP encryption fails)', () => {
      const ecKeys = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      // EC keys have "BEGIN PUBLIC KEY" marker but RSA-OAEP encryption fails
      // validateKeyPair attempts OAEP encrypt/decrypt which throws for EC keys
      const result = validateKeyPair(ecKeys.publicKey, ecKeys.privateKey);
      expect(result).toBe(false);
    });

    it('should return false for mixing RSA public with EC private', () => {
      const ecKeys = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const result = validateKeyPair(validKeyPair.publicKey, ecKeys.privateKey);
      expect(result).toBe(false);
    });

    it('should return false for mixing EC public with RSA private', () => {
      const ecKeys = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const result = validateKeyPair(ecKeys.publicKey, validKeyPair.privateKey);
      expect(result).toBe(false);
    });
  });

  describe('Different RSA Key Sizes', () => {
    it('should validate 2048-bit RSA key pair', () => {
      const smallKeys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const result = validateKeyPair(smallKeys.publicKey, smallKeys.privateKey);
      expect(result).toBe(true);
    });

    it('should return false for mismatched 2048-bit and 4096-bit keys', () => {
      const smallKeys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      // 2048-bit public key + 4096-bit private key
      const result = validateKeyPair(smallKeys.publicKey, validKeyPair.privateKey);
      expect(result).toBe(false);
    });
  });

  describe('PEM Format Variations', () => {
    it('should validate PKCS#1 formatted keys (RSA PUBLIC KEY / RSA PRIVATE KEY)', () => {
      const pkcs1Keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
      });

      // PKCS#1 uses "RSA PUBLIC KEY" not "PUBLIC KEY"
      // validateKeyPair checks for "BEGIN PUBLIC KEY" which won't match PKCS#1
      const result = validateKeyPair(pkcs1Keys.publicKey, pkcs1Keys.privateKey);
      expect(result).toBe(false);
    });

    it('should validate mixed SPKI public + PKCS#8 private (standard format)', () => {
      // This is what generateKeyPair produces
      const result = validateKeyPair(validKeyPair.publicKey, validKeyPair.privateKey);
      expect(result).toBe(true);
    });
  });

  describe('Corrupted Keys', () => {
    it('should return false for truncated public key', () => {
      const truncated = validKeyPair.publicKey.slice(0, 100);
      const result = validateKeyPair(truncated, validKeyPair.privateKey);
      expect(result).toBe(false);
    });

    it('should return false for truncated private key', () => {
      const truncated = validKeyPair.privateKey.slice(0, 100);
      const result = validateKeyPair(validKeyPair.publicKey, truncated);
      expect(result).toBe(false);
    });

    it('should return false for public key with modified content', () => {
      // Modify a character in the base64 content
      const lines = validKeyPair.publicKey.split('\n');
      if (lines[1]) {
        lines[1] = lines[1].slice(0, 10) + 'X' + lines[1].slice(11);
      }
      const modified = lines.join('\n');
      const result = validateKeyPair(modified, validKeyPair.privateKey);
      expect(result).toBe(false);
    });

    it('should return false for private key with modified content', () => {
      const lines = validKeyPair.privateKey.split('\n');
      if (lines[1]) {
        lines[1] = lines[1].slice(0, 10) + 'X' + lines[1].slice(11);
      }
      const modified = lines.join('\n');
      const result = validateKeyPair(validKeyPair.publicKey, modified);
      expect(result).toBe(false);
    });
  });

  describe('Return Type', () => {
    it('should always return a boolean', () => {
      expect(typeof validateKeyPair(validKeyPair.publicKey, validKeyPair.privateKey)).toBe('boolean');
      expect(typeof validateKeyPair('', '')).toBe('boolean');
      expect(typeof validateKeyPair('invalid', 'invalid')).toBe('boolean');
    });

    it('should return primitive boolean, not Boolean object', () => {
      const result = validateKeyPair(validKeyPair.publicKey, validKeyPair.privateKey);
      expect(result).not.toBeInstanceOf(Boolean);
      expect(Object.prototype.toString.call(result)).toBe('[object Boolean]');
    });
  });
});

describe('Cross-Function Integration', () => {
  describe('Key Generation and Validation Workflow', () => {
    it('should generate keys that pass validation', async () => {
      const keyPair = await generateKeyPair();
      const isValid = validateKeyPair(keyPair.publicKey, keyPair.privateKey);
      expect(isValid).toBe(true);
    });

    it('should generate keys with fingerprint matching calculateKeyFingerprint', async () => {
      const keyPair = await generateKeyPair();
      const recalculated = calculateKeyFingerprint(keyPair.publicKey);
      expect(keyPair.publicKeyFingerprint).toBe(recalculated);
    });
  });

  describe('Complete Key Lifecycle', () => {
    it('should support full key lifecycle: generate, validate, use, verify fingerprint', async () => {
      // 1. Generate key pair
      const keyPair = await generateKeyPair();

      // 2. Validate key pair
      expect(validateKeyPair(keyPair.publicKey, keyPair.privateKey)).toBe(true);

      // 3. Verify fingerprint
      expect(keyPair.publicKeyFingerprint).toBe(calculateKeyFingerprint(keyPair.publicKey));

      // 4. Use keys for encryption
      const testData = Buffer.from('Lifecycle test data');
      const encrypted = crypto.publicEncrypt(
        {
          key: keyPair.publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        testData
      );

      const decrypted = crypto.privateDecrypt(
        {
          key: keyPair.privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        encrypted
      );

      expect(decrypted.equals(testData)).toBe(true);

      // 5. Use keys for signing
      const signature = crypto.sign('sha256', testData, {
        key: keyPair.privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      });

      const verified = crypto.verify('sha256', testData, {
        key: keyPair.publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      }, signature);

      expect(verified).toBe(true);
    });
  });

  describe('Fingerprint Lookup Simulation', () => {
    it('should support finding keys by fingerprint', async () => {
      // Simulate a key registry with multiple key pairs
      const keyRegistry = new Map<string, GeneratedKeyPair>();

      // Add existing keys to registry
      keyRegistry.set(validKeyPair.publicKeyFingerprint, validKeyPair);
      keyRegistry.set(secondValidKeyPair.publicKeyFingerprint, secondValidKeyPair);

      // Generate a new key pair
      const newKeyPair = await generateKeyPair();
      keyRegistry.set(newKeyPair.publicKeyFingerprint, newKeyPair);

      // Look up by fingerprint
      const lookupFingerprint = calculateKeyFingerprint(newKeyPair.publicKey);
      const foundKeyPair = keyRegistry.get(lookupFingerprint);

      expect(foundKeyPair).toBeDefined();
      expect(foundKeyPair?.publicKey).toBe(newKeyPair.publicKey);
      expect(foundKeyPair?.privateKey).toBe(newKeyPair.privateKey);
    });
  });
});

describe('GeneratedKeyPair Interface', () => {
  describe('Type Constraints', () => {
    it('should have algorithm as literal type RSA-4096', () => {
      // TypeScript compile-time check - at runtime verify the value
      const algorithm: 'RSA-4096' = validKeyPair.algorithm;
      expect(algorithm).toBe('RSA-4096');
    });

    it('should have keySize as literal type 4096', () => {
      const keySize: 4096 = validKeyPair.keySize;
      expect(keySize).toBe(4096);
    });

    it('should have publicExponent as literal type 65537', () => {
      const exponent: 65537 = validKeyPair.publicExponent;
      expect(exponent).toBe(65537);
    });
  });
});
