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
import { generateKeyPair, type GeneratedKeyPair } from '../../src/internal/crypto/key-generator.js';
import type { EncryptedFile } from '../../src/types/index.js';
import { rsa4096KeyPair } from '../fixtures/rsa-keys.js';

/** Build a minimal canonical string for signature tests */
function buildTestCanonicalString() {
  const files: EncryptedFile[] = [{
    fileId: 'file_test1',
    encryptedFilename: 'enc_name',
    filenameIV: generateIV(),
    filenameAuthTag: crypto.randomBytes(16).toString('base64url'),
    mimetype: 'text/plain',
    size: 100,
    originalSize: 100,
    hash: computeHash(Buffer.from('test')),
    hashAlgorithm: 'SHA-256',
    iv: generateIV(),
    authTag: crypto.randomBytes(16).toString('base64url'),
  }];
  return buildCanonicalString({
    packageId: 'capsa_test123',
    version: '1.0.0',
    totalSize: 100,
    algorithm: 'AES-256-GCM',
    creatorPartyId: 'creator_1',
    creatorKeyFingerprint: 'ab'.repeat(32),
    files,
    subjectIV: generateIV(),
  });
}

const keyPair = rsa4096KeyPair(0);
const keyPair2 = rsa4096KeyPair(1);

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
  let kp1: GeneratedKeyPair;
  let kp2: GeneratedKeyPair;

  // RSA-4096 prime search is slow and variable; both pairs generate concurrently
  beforeAll(async () => {
    [kp1, kp2] = await Promise.all([generateKeyPair(), generateKeyPair()]);
  }, 60_000);

  it('should generate RSA-4096 key pair', () => {
    expect(kp1.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(kp1.privateKey).toContain('BEGIN PRIVATE KEY');
    expect(kp1.publicKeyFingerprint).toBeTruthy();
  });

  it('should generate SHA-256 fingerprint', () => {
    expect(kp1.publicKeyFingerprint).toMatch(/^[a-f0-9]{64}$/);
  });

  it('should generate unique key pairs', () => {
    expect(kp1.publicKeyFingerprint).not.toBe(kp2.publicKeyFingerprint);
    expect(kp1.publicKey).not.toBe(kp2.publicKey);
  });

  it('should generate valid RSA key pair', () => {
    const result = kp1;

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
