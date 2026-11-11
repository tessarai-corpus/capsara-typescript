/**
 * Vitest global setup: generates the shared RSA test key pairs once per run.
 * @file tests/fixtures/rsa-keys.setup.ts
 */

import { generateKeyPair } from 'crypto';
import { promisify } from 'util';
import type { TestProject } from 'vitest/node';
import type { TestKeyPair } from './rsa-keys.js';

/** Number of distinct RSA-4096 key pairs available to each test file. */
export const RSA_4096_POOL_SIZE = 4;

const generateKeyPairAsync = promisify(generateKeyPair);

function generateRsaKeyPair(modulusLength: number): Promise<TestKeyPair> {
  return generateKeyPairAsync('rsa', {
    modulusLength,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

export default async function setup(project: TestProject): Promise<void> {
  const [rsa2048, ...rsa4096] = await Promise.all([
    generateRsaKeyPair(2048),
    ...Array.from({ length: RSA_4096_POOL_SIZE }, () => generateRsaKeyPair(4096)),
  ]);
  project.provide('rsaKeys', { rsa4096, rsa2048: rsa2048! });
}
