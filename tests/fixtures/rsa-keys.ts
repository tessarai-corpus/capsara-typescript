/**
 * Shared RSA test key pairs, generated once per run by rsa-keys.setup.ts.
 * @file tests/fixtures/rsa-keys.ts
 */

import * as crypto from 'crypto';
import { inject } from 'vitest';
import { RSA_4096_POOL_SIZE } from './rsa-keys.setup.js';

export interface TestKeyPair {
  publicKey: string;
  privateKey: string;
}

export interface TestRsaKeys {
  rsa4096: TestKeyPair[];
  rsa2048: TestKeyPair;
}

declare module 'vitest' {
  export interface ProvidedContext {
    rsaKeys: TestRsaKeys;
  }
}

/** Returns a distinct RSA-4096 key pair (SPKI/PKCS#8 PEM) for each index. */
export function rsa4096KeyPair(index = 0): TestKeyPair {
  const keyPair = inject('rsaKeys').rsa4096[index];
  if (!keyPair) {
    throw new Error(`Only ${RSA_4096_POOL_SIZE} shared RSA-4096 test key pairs exist; index ${index} requested`);
  }
  return keyPair;
}

/** Returns an RSA-2048 key pair (SPKI/PKCS#8 PEM), below the SDK's minimum key size. */
export function rsa2048KeyPair(): TestKeyPair {
  return inject('rsaKeys').rsa2048;
}

/** Re-encodes a key pair as PKCS#1 PEM ("RSA PUBLIC KEY" / "RSA PRIVATE KEY"). */
export function toPkcs1(keyPair: TestKeyPair): TestKeyPair {
  return {
    publicKey: crypto.createPublicKey(keyPair.publicKey).export({ type: 'pkcs1', format: 'pem' }).toString(),
    privateKey: crypto.createPrivateKey(keyPair.privateKey).export({ type: 'pkcs1', format: 'pem' }).toString(),
  };
}
