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
  calculatePrivateKeyFingerprint,
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
  [validKeyPair, secondValidKeyPair] = await Promise.all([generateKeyPair(), generateKeyPair()]);
}, 60_000);

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
    it('should return a Promise', async () => {
      const result = generateKeyPair();
      expect(result).toBeInstanceOf(Promise);
      await result;
    }, 30_000);

    it('should resolve successfully', async () => {
      const result = await generateKeyPair();
      expect(result).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey).toBeDefined();
    }, 30_000);
  });
});

describe('calculateKeyFingerprint', () => {
  function derFingerprint(pem: string): string {
    const der = crypto.createPublicKey(pem).export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(der).digest('hex');
  }

  describe('Output Format', () => {
    it('should return 64 lowercase hex characters (SHA-256)', () => {
      const fingerprint = calculateKeyFingerprint(validKeyPair.publicKey);
      expect(fingerprint).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('Definition: SHA-256 of the DER SubjectPublicKeyInfo', () => {
    it('should hash the DER SPKI bytes, not the PEM text', () => {
      const fingerprint = calculateKeyFingerprint(validKeyPair.publicKey);
      const pemTextHash = crypto.createHash('sha256').update(validKeyPair.publicKey).digest('hex');

      expect(fingerprint).toBe(derFingerprint(validKeyPair.publicKey));
      expect(fingerprint).not.toBe(pemTextHash);
    });

    it('should give the same fingerprint for LF, CRLF and no-trailing-newline PEMs', () => {
      const lf = validKeyPair.publicKey.replace(/\r\n/g, '\n');
      const crlf = lf.replace(/\n/g, '\r\n');
      const noTrailingNewline = lf.trimEnd();

      const expected = calculateKeyFingerprint(lf);
      expect(calculateKeyFingerprint(crlf)).toBe(expected);
      expect(calculateKeyFingerprint(noTrailingNewline)).toBe(expected);
      expect(calculateKeyFingerprint(`${lf}\n\n`)).toBe(expected);
    });

    it('should reject a PKCS#1 public key PEM (SPKI only)', () => {
      const pkcs1PEM = crypto
        .createPublicKey(validKeyPair.publicKey)
        .export({ type: 'pkcs1', format: 'pem' }) as string;

      expect(() => calculateKeyFingerprint(pkcs1PEM)).toThrow('SPKI');
    });

    it('should generate SPKI public keys', () => {
      expect(validKeyPair.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
    });

    it('should reject a PKCS#8 private key PEM', () => {
      expect(() => calculateKeyFingerprint(validKeyPair.privateKey)).toThrow('SPKI');
    });

    it('should reject a PKCS#1 private key PEM', () => {
      const pkcs1Private = crypto
        .createPrivateKey(validKeyPair.privateKey)
        .export({ type: 'pkcs1', format: 'pem' }) as string;
      expect(() => calculateKeyFingerprint(pkcs1Private)).toThrow('SPKI');
    });

    it('should reject a private key placed before a public key in the same text', () => {
      expect(() => calculateKeyFingerprint(`${validKeyPair.privateKey}\n${validKeyPair.publicKey}`)).toThrow('SPKI');
    });

    it('should reject a non-RSA SPKI public key', () => {
      const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const ecPem = ec.publicKey.export({ type: 'spki', format: 'pem' }) as string;
      const ed = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }) as string;
      expect(() => calculateKeyFingerprint(ecPem)).toThrow('RSA');
      expect(() => calculateKeyFingerprint(ed)).toThrow('RSA');
      expect(() => calculateKeyFingerprint(ec.publicKey)).toThrow('RSA');
    });

    it('should accept a public KeyObject and reject a private one', () => {
      const keyObject = crypto.createPublicKey(validKeyPair.publicKey);
      expect(calculateKeyFingerprint(keyObject)).toBe(calculateKeyFingerprint(validKeyPair.publicKey));
      const privateObject = crypto.createPrivateKey(validKeyPair.privateKey);
      expect(() => calculateKeyFingerprint(privateObject)).toThrow('private key');
    });  });

  describe('calculatePrivateKeyFingerprint', () => {
    it('should give a private key the fingerprint of its public half', () => {
      expect(calculatePrivateKeyFingerprint(validKeyPair.privateKey)).toBe(calculateKeyFingerprint(validKeyPair.publicKey));
    });

    it('should accept PKCS#1 private keys and private KeyObjects', () => {
      const privateObject = crypto.createPrivateKey(validKeyPair.privateKey);
      const pkcs1 = privateObject.export({ type: 'pkcs1', format: 'pem' }) as string;
      const expected = calculateKeyFingerprint(validKeyPair.publicKey);
      expect(calculatePrivateKeyFingerprint(pkcs1)).toBe(expected);
      expect(calculatePrivateKeyFingerprint(privateObject)).toBe(expected);
    });

    it('should reject public keys and non-RSA private keys', () => {
      expect(() => calculatePrivateKeyFingerprint(validKeyPair.publicKey)).toThrow();
      expect(() => calculatePrivateKeyFingerprint(crypto.createPublicKey(validKeyPair.publicKey))).toThrow('RSA private key');
      const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
      expect(() => calculatePrivateKeyFingerprint(ec)).toThrow('RSA private key');
    });
  });

  describe('Consistency and uniqueness', () => {
    it('should return same fingerprint for same input', () => {
      expect(calculateKeyFingerprint(validKeyPair.publicKey)).toBe(calculateKeyFingerprint(validKeyPair.publicKey));
    });

    it('should return different fingerprint for different keys', () => {
      expect(calculateKeyFingerprint(validKeyPair.publicKey)).not.toBe(
        calculateKeyFingerprint(secondValidKeyPair.publicKey)
      );
    });
  });

  describe('Invalid input', () => {
    it.each([
      ['empty string', ''],
      ['plain text', 'hello'],
      ['PEM with garbage body', '-----BEGIN PUBLIC KEY-----\nnotbase64!!\n-----END PUBLIC KEY-----'],
    ])('should throw for %s', (_label, input) => {
      expect(() => calculateKeyFingerprint(input)).toThrow();
    });
  });
});

describe('Cross-Function Integration', () => {
  describe('Key Generation Workflow', () => {
    it('should generate keys with fingerprint matching calculateKeyFingerprint', () => {
      const keyPair = validKeyPair;
      const recalculated = calculateKeyFingerprint(keyPair.publicKey);
      expect(keyPair.publicKeyFingerprint).toBe(recalculated);
    });
  });

  describe('Complete Key Lifecycle', () => {
    it('should support full key lifecycle: generate, verify fingerprint, use', () => {
      // 1. Key pair from generateKeyPair()
      const keyPair = validKeyPair;

      // 2. Verify fingerprint
      expect(keyPair.publicKeyFingerprint).toBe(calculateKeyFingerprint(keyPair.publicKey));

      // 3. Use keys for encryption
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

      // 4. Use keys for signing
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
    it('should support finding keys by fingerprint', () => {
      // Simulate a key registry with multiple key pairs
      const keyRegistry = new Map<string, GeneratedKeyPair>();

      // Add an existing key to the registry
      keyRegistry.set(validKeyPair.publicKeyFingerprint, validKeyPair);

      // Register a newly generated key pair
      const newKeyPair = secondValidKeyPair;
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
