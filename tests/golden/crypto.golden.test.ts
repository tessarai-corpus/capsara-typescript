/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Crypto Operations
 * Tests AES-GCM, RSA, key generation, JWS signatures, and IV uniqueness.
 */

import * as crypto from 'crypto';
import {
  generateMasterKey,
  generateIV,
  encryptAES,
  decryptAES,
  encryptMasterKeyForParty,
  decryptMasterKey,
  computeHash,
} from '../../src/internal/crypto/primitives.js';
import { createCapsaSignature, verifyCapsaSignature, buildCanonicalString } from '../../src/internal/crypto/signatures.js';
import { generateKeyPair } from '../../src/internal/crypto/key-generator.js';
import type { EncryptedFile } from '../../src/types/index.js';

function generateTestKeyPair(modulusLength = 4096) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

/** Build a minimal canonical string for signature tests */
function buildTestCanonicalString() {
  const files: EncryptedFile[] = [{
    fileId: 'file_test1',
    encryptedFilename: 'enc_name',
    filenameIV: generateIV(),
    mimetype: 'text/plain',
    size: 100,
    originalSize: 100,
    hash: computeHash(Buffer.from('test')),
    iv: generateIV(),
    authTag: crypto.randomBytes(16).toString('base64url'),
    blobPath: 'blob/path',
  }];
  return buildCanonicalString({
    packageId: 'capsa_test123',
    version: '1.0.0',
    totalSize: 100,
    algorithm: 'AES-256-GCM',
    files,
    subjectIV: generateIV(),
  });
}

let keyPair: { publicKey: string; privateKey: string };
let keyPair2: { publicKey: string; privateKey: string };

beforeAll(() => {
  keyPair = generateTestKeyPair(4096);
  keyPair2 = generateTestKeyPair(4096);
});

describe('Golden: AES-GCM', () => {
  it('should roundtrip encrypt/decrypt', () => {
    const key = generateMasterKey();
    const plaintext = Buffer.from('Hello, golden tests!');

    const encrypted = encryptAES(plaintext, key);
    const decrypted = decryptAES(encrypted.encryptedData, key, encrypted.iv, encrypted.authTag);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('should fail decryption with wrong key', () => {
    const key1 = generateMasterKey();
    const key2 = generateMasterKey();

    const encrypted = encryptAES(Buffer.from('secret'), key1);

    expect(() => decryptAES(encrypted.encryptedData, key2, encrypted.iv, encrypted.authTag))
      .toThrow();
  });

  it('should fail decryption with wrong IV', () => {
    const key = generateMasterKey();

    const encrypted = encryptAES(Buffer.from('secret'), key);
    const wrongIV = crypto.randomBytes(12).toString('base64url');

    expect(() => decryptAES(encrypted.encryptedData, key, wrongIV, encrypted.authTag))
      .toThrow();
  });

  it('should fail decryption with wrong auth tag', () => {
    const key = generateMasterKey();

    const encrypted = encryptAES(Buffer.from('secret'), key);
    const wrongTag = crypto.randomBytes(16).toString('base64url');

    expect(() => decryptAES(encrypted.encryptedData, key, encrypted.iv, wrongTag))
      .toThrow();
  });

  it('should fail with tampered ciphertext', () => {
    const key = generateMasterKey();

    const encrypted = encryptAES(Buffer.from('secret data'), key);
    // Tamper with the base64url-encoded ciphertext
    const tamperedBuffer = Buffer.from(encrypted.encryptedData, 'base64url');
    tamperedBuffer[0] = (tamperedBuffer[0]! ^ 0xff);
    const tampered = tamperedBuffer.toString('base64url');

    expect(() => decryptAES(tampered, key, encrypted.iv, encrypted.authTag))
      .toThrow();
  });
});

describe('Golden: RSA', () => {
  it('should roundtrip encrypt/decrypt master key', () => {
    const masterKey = generateMasterKey();

    const encrypted = encryptMasterKeyForParty(masterKey, keyPair.publicKey);
    const decrypted = decryptMasterKey(encrypted, keyPair.privateKey);

    expect(decrypted.equals(masterKey)).toBe(true);
  });

  it('should fail decryption with wrong private key', () => {
    const masterKey = generateMasterKey();
    const encrypted = encryptMasterKeyForParty(masterKey, keyPair.publicKey);

    expect(() => decryptMasterKey(encrypted, keyPair2.privateKey)).toThrow();
  });

  it('should produce 512-byte encrypted output for RSA-4096', () => {
    const masterKey = generateMasterKey();
    const encrypted = encryptMasterKeyForParty(masterKey, keyPair.publicKey);

    // base64url-encoded 512 bytes = 683 chars
    const rawBytes = Buffer.from(encrypted, 'base64url');
    expect(rawBytes.length).toBe(512);
  });

  it('should validate RSA key is in PEM format', () => {
    expect(keyPair.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(keyPair.privateKey).toContain('BEGIN PRIVATE KEY');
  });
});

describe('Golden: Key Generation', () => {
  it('should generate RSA-4096 key pair', async () => {
    const result = await generateKeyPair();
    expect(result.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(result.privateKey).toContain('BEGIN PRIVATE KEY');
    expect(result.publicKeyFingerprint).toBeTruthy();
  });

  it('should generate SHA-256 fingerprint', async () => {
    const result = await generateKeyPair();
    expect(result.publicKeyFingerprint).toMatch(/^[a-f0-9]{64}$/);
  });

  it('should generate unique key pairs', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    expect(kp1.publicKeyFingerprint).not.toBe(kp2.publicKeyFingerprint);
    expect(kp1.publicKey).not.toBe(kp2.publicKey);
  }, 30_000);

  it('should generate valid RSA key pair', async () => {
    const result = await generateKeyPair();

    // Verify by roundtrip encrypt/decrypt
    const masterKey = generateMasterKey();
    const encrypted = encryptMasterKeyForParty(masterKey, result.publicKey);
    const decrypted = decryptMasterKey(encrypted, result.privateKey);
    expect(decrypted.equals(masterKey)).toBe(true);
  });
});

describe('Golden: JWS Signatures', () => {
  it('should roundtrip sign/verify', () => {
    const canonical = buildTestCanonicalString();
    const signature = createCapsaSignature(canonical, keyPair.privateKey);
    const valid = verifyCapsaSignature(signature, canonical, keyPair.publicKey);
    expect(valid).toBe(true);
  });

  it('should fail verification with tampered canonical string', () => {
    const canonical = buildTestCanonicalString();
    const signature = createCapsaSignature(canonical, keyPair.privateKey);
    const tampered = canonical + '|tampered';
    const valid = verifyCapsaSignature(signature, tampered, keyPair.publicKey);
    expect(valid).toBe(false);
  });

  it('should fail verification with wrong public key', () => {
    const canonical = buildTestCanonicalString();
    const signature = createCapsaSignature(canonical, keyPair.privateKey);
    const valid = verifyCapsaSignature(signature, canonical, keyPair2.publicKey);
    expect(valid).toBe(false);
  });

  it('should produce RS256 algorithm in signature', () => {
    const canonical = buildTestCanonicalString();
    const signature = createCapsaSignature(canonical, keyPair.privateKey);
    expect(signature.algorithm).toBe('RS256');
    expect(signature.protected).toBeTruthy();
    expect(signature.payload).toBeTruthy();
    expect(signature.signature).toBeTruthy();
  });
});

describe('Golden: IV Uniqueness', () => {
  it('should generate unique IVs across many calls', () => {
    const ivs = new Set<string>();
    for (let i = 0; i < 100; i++) {
      ivs.add(generateIV());
    }
    expect(ivs.size).toBe(100);
  });

  it('should generate base64url-encoded 12-byte (96-bit) IVs', () => {
    const iv = generateIV();
    // generateIV returns base64url string
    const ivBuffer = Buffer.from(iv, 'base64url');
    expect(ivBuffer.length).toBe(12);
  });

  it('should generate 32-byte (256-bit) master keys', () => {
    const key = generateMasterKey();
    expect(key.length).toBe(32);
  });
});

describe('Golden: SHA-256 Hash', () => {
  it('should compute deterministic hash', () => {
    const data = Buffer.from('test data');
    const hash1 = computeHash(data);
    const hash2 = computeHash(data);
    expect(hash1).toBe(hash2);
  });

  it('should produce 64-char hex string', () => {
    const hash = computeHash(Buffer.from('data'));
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });
});
