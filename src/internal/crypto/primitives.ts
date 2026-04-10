/** AES-256-GCM, RSA-4096-OAEP-SHA256, and SHA-256 cryptographic primitives. */

import * as crypto from 'crypto';
import type { AESEncryptionResult } from '../types.js';

/**
 * @throws Error if key size is below minBits or cannot be determined
 */
function validateRSAKeySize(keyObject: crypto.KeyObject, minBits: number = 4096): void {
  const keyDetails = keyObject.asymmetricKeyDetails;
  if (!keyDetails) {
    throw new Error('Unable to extract key details');
  }

  const modulusLength = keyDetails.modulusLength;
  if (!modulusLength || modulusLength < minBits) {
    throw new Error(
      `RSA key size too small: expected at least ${minBits} bits, got ${modulusLength || 'unknown'} bits`
    );
  }
}

/** Generate a 256-bit AES master key. */
export function generateMasterKey(): Buffer {
  return crypto.randomBytes(32); // 256 bits
}

/**
 * Generate a 96-bit initialization vector for AES-GCM.
 * Used for optional fields (subject, body, metadata) that need separate IVs.
 * encryptAES() generates its own IV automatically for file content.
 */
export function generateIV(): string {
  const iv = crypto.randomBytes(12); // 96 bits for GCM
  return iv.toString('base64url');
}

/**
 * Encrypt data using AES-256-GCM.
 * @param key - 256-bit AES key (32 bytes)
 * @returns Encrypted data with IV and authentication tag, all base64url-encoded
 * @throws Error if key is not 32 bytes
 */
export function encryptAES(data: Buffer, key: Buffer): AESEncryptionResult {
  if (key.length !== 32) {
    throw new Error(`Invalid key length: expected 32 bytes (AES-256), got ${key.length} bytes`);
  }

  const iv = crypto.randomBytes(12); // 96 bits for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encryptedData: encrypted.toString('base64url'),
    iv: iv.toString('base64url'),
    authTag: authTag.toString('base64url'),
  };
}

/**
 * Decrypt data using AES-256-GCM.
 * @param encryptedData - Base64url-encoded ciphertext
 * @param key - 256-bit AES key (32 bytes)
 * @param iv - Base64url-encoded 12-byte IV
 * @param authTag - Base64url-encoded 16-byte authentication tag
 * @throws Error if key length is invalid, authentication fails, or decryption fails
 */
export function decryptAES(
  encryptedData: string,
  key: Buffer,
  iv: string,
  authTag: string
): Buffer {
  if (key.length !== 32) {
    throw new Error(`Invalid key length: expected 32 bytes (AES-256), got ${key.length} bytes`);
  }

  let ivBuffer: Buffer;
  try {
    ivBuffer = Buffer.from(iv, 'base64url');
    if (ivBuffer.length !== 12) {
      throw new Error('Invalid IV length');
    }
  } catch {
    throw new Error('Invalid IV: must be 12-byte base64url-encoded value');
  }

  let authTagBuffer: Buffer;
  try {
    authTagBuffer = Buffer.from(authTag, 'base64url');
    if (authTagBuffer.length !== 16) {
      throw new Error('Invalid auth tag length');
    }
  } catch {
    throw new Error('Invalid auth tag: must be 16-byte base64url-encoded value');
  }

  let encryptedBuffer: Buffer;
  try {
    encryptedBuffer = Buffer.from(encryptedData, 'base64url');
  } catch {
    throw new Error('Invalid encrypted data: must be base64url-encoded');
  }

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, ivBuffer);
    decipher.setAuthTag(authTagBuffer);

    return Buffer.concat([
      decipher.update(encryptedBuffer),
      decipher.final(),
    ]);
  } catch {
    // Generic error message to avoid leaking information
    throw new Error('AES-GCM decryption failed: authentication failed or corrupted ciphertext');
  }
}

/**
 * Encrypt master key for a party using their RSA-4096 public key.
 * @param masterKey - 32-byte AES master key
 * @param publicKeyPEM - Party's RSA public key in PEM format
 * @returns Base64url-encoded encrypted master key
 * @throws Error if masterKey is not 32 bytes or publicKeyPEM is invalid
 */
export function encryptMasterKeyForParty(
  masterKey: Buffer,
  publicKeyPEM: string
): string {
  if (masterKey.length !== 32) {
    throw new Error(`Invalid master key length: expected 32 bytes, got ${masterKey.length} bytes`);
  }

  if (!publicKeyPEM || typeof publicKeyPEM !== 'string') {
    throw new Error('publicKeyPEM must be a non-empty string');
  }
  if (!publicKeyPEM.includes('BEGIN PUBLIC KEY') && !publicKeyPEM.includes('BEGIN RSA PUBLIC KEY')) {
    throw new Error('publicKeyPEM must be in PEM format');
  }

  let publicKeyObject: crypto.KeyObject;
  try {
    publicKeyObject = crypto.createPublicKey({
      key: publicKeyPEM,
      format: 'pem',
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Invalid public key PEM: ${message}`);
  }

  validateRSAKeySize(publicKeyObject, 4096);

  const encrypted = crypto.publicEncrypt(
    {
      key: publicKeyObject,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    masterKey
  );

  return encrypted.toString('base64url');
}

/**
 * Decrypt master key using party's RSA-4096 private key.
 * @param encryptedKey - Base64url-encoded encrypted master key
 * @param privateKeyPEM - Party's RSA private key in PEM format
 * @returns Decrypted master key (32 bytes)
 * @throws Error if privateKeyPEM is invalid or decryption fails
 */
export function decryptMasterKey(
  encryptedKey: string,
  privateKeyPEM: string
): Buffer {
  if (!privateKeyPEM || typeof privateKeyPEM !== 'string') {
    throw new Error('privateKeyPEM must be a non-empty string');
  }
  if (!privateKeyPEM.includes('BEGIN PRIVATE KEY') && !privateKeyPEM.includes('BEGIN RSA PRIVATE KEY')) {
    throw new Error('privateKeyPEM must be in PEM format');
  }

  let privateKeyObject: crypto.KeyObject;
  try {
    privateKeyObject = crypto.createPrivateKey({
      key: privateKeyPEM,
      format: 'pem',
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Invalid private key PEM: ${message}`);
  }

  validateRSAKeySize(privateKeyObject, 4096);

  try {
    const encryptedBuffer = Buffer.from(encryptedKey, 'base64url');

    return crypto.privateDecrypt(
      {
        key: privateKeyObject,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encryptedBuffer
    );
  } catch {
    // Generic error to prevent padding oracle attacks via OpenSSL error detail leakage
    throw new Error('RSA-OAEP decryption failed');
  }
}

/**
 * Encrypt data using AES-256-GCM, returning raw Buffers instead of base64url.
 * Avoids base64 round-trip overhead for large file content.
 * @param key - 256-bit AES key (32 bytes)
 * @throws Error if key is not 32 bytes
 */
export function encryptAESRaw(data: Buffer, key: Buffer): { encryptedData: Buffer; iv: Buffer; authTag: Buffer } {
  if (key.length !== 32) {
    throw new Error(`Invalid key length: expected 32 bytes (AES-256), got ${key.length} bytes`);
  }

  const iv = crypto.randomBytes(12); // 96 bits for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { encryptedData: encrypted, iv, authTag };
}

/**
 * Decrypt data using AES-256-GCM with raw Buffer inputs.
 * Avoids base64 round-trip overhead for large file content.
 * @param key - 256-bit AES key (32 bytes)
 * @param iv - 12-byte initialization vector
 * @param authTag - 16-byte authentication tag
 * @throws Error if authentication fails or decryption fails
 */
export function decryptAESRaw(
  encryptedData: Buffer,
  key: Buffer,
  iv: Buffer,
  authTag: Buffer
): Buffer {
  if (key.length !== 32) {
    throw new Error(`Invalid key length: expected 32 bytes (AES-256), got ${key.length} bytes`);
  }
  if (iv.length !== 12) {
    throw new Error('Invalid IV: must be 12 bytes');
  }
  if (authTag.length !== 16) {
    throw new Error('Invalid auth tag: must be 16 bytes');
  }

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]);
  } catch {
    throw new Error('AES-GCM decryption failed: authentication failed or corrupted ciphertext');
  }
}

/** Compute SHA-256 hash, returned as lowercase hex. */
export function computeHash(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex').toLowerCase();
}

/** Generate a cryptographically secure random ID, returned as base64url. */
export function generateSecureId(length: number = 16): string {
  return crypto.randomBytes(length).toString('base64url');
}
