/** RSA-4096 key pair generation and validation. */

import * as crypto from 'crypto';
import { promisify } from 'util';

const generateKeyPairAsync = promisify(crypto.generateKeyPair);

export interface GeneratedKeyPair {
  publicKey: string;               // PEM, SPKI format
  privateKey: string;              // PEM, PKCS#8 format
  publicKeyFingerprint: string;    // SHA-256 hex
  algorithm: 'RSA-4096';
  keySize: 4096;
  publicExponent: 65537;
}

/**
 * Generate RSA-4096 key pair for use with Capsara API.
 * Private key must be stored securely by the application (password-protected storage).
 * Public key should be uploaded to the API via AccountClient.addPublicKey().
 */
export async function generateKeyPair(): Promise<GeneratedKeyPair> {
  const { publicKey, privateKey } = await generateKeyPairAsync('rsa', {
    modulusLength: 4096,
    publicExponent: 65537,
    publicKeyEncoding: {
      type: 'spki',  // X.509 SubjectPublicKeyInfo
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8', // PKCS#8
      format: 'pem',
    },
  });

  const fingerprint = calculateKeyFingerprint(publicKey);

  return {
    publicKey,
    privateKey,
    publicKeyFingerprint: fingerprint,
    algorithm: 'RSA-4096',
    keySize: 4096,
    publicExponent: 65537,
  };
}

/**
 * Calculate SHA-256 fingerprint of public key.
 * Matches API's computeKeyFingerprint: hashes the entire PEM string including headers/footers.
 */
export function calculateKeyFingerprint(publicKeyPEM: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(publicKeyPEM);
  return hash.digest('hex');
}

/** Validate that public and private keys are PEM-formatted and form a working pair. */
export function validateKeyPair(publicKey: string, privateKey: string): boolean {
  try {
    if (!publicKey.includes('BEGIN PUBLIC KEY') || !privateKey.includes('BEGIN PRIVATE KEY')) {
      return false;
    }

    const testData = Buffer.from('test-validation-data');

    const encrypted = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      testData
    );

    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encrypted
    );

    return decrypted.equals(testData);
  } catch {
    return false;
  }
}
