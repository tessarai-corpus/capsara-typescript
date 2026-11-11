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

function spkiFingerprint(publicKey: crypto.KeyObject): string {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

export function calculateKeyFingerprint(key: string | crypto.KeyObject): string {
  let publicKey: crypto.KeyObject;
  if (typeof key === 'string') {
    if (!key.startsWith('-----BEGIN PUBLIC KEY-----')) {
      throw new Error('Public key must be an SPKI PEM (BEGIN PUBLIC KEY)');
    }
    publicKey = crypto.createPublicKey({ key, format: 'pem' });
  } else {
    if (key.type !== 'public') {
      throw new Error('Public key must be an SPKI public key, not a private key');
    }
    publicKey = key;
  }
  if (publicKey.asymmetricKeyType !== 'rsa') {
    throw new Error('Public key must be an RSA key');
  }
  return spkiFingerprint(publicKey);
}

export function calculatePrivateKeyFingerprint(key: string | crypto.KeyObject): string {
  const privateKey = typeof key === 'string' ? crypto.createPrivateKey({ key, format: 'pem' }) : key;
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'rsa') {
    throw new Error('Private key must be an RSA private key');
  }
  return spkiFingerprint(crypto.createPublicKey(privateKey));
}

/** Validate that public and private keys are PEM-formatted and form a working pair. */
