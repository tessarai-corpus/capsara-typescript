/** JWS RS256 (RSA-SHA256) signature creation and verification for capsas. */

import * as crypto from 'crypto';
import type { CapsaSignature, EncryptedFile } from '../../types/index.js';

function validateEncryptedFile(file: EncryptedFile, index: number): void {
  if (!file.hash || typeof file.hash !== 'string') {
    throw new Error(`File at index ${index} missing required field: hash`);
  }
  if (!file.iv || typeof file.iv !== 'string') {
    throw new Error(`File at index ${index} missing required field: iv`);
  }
  if (!file.filenameIV || typeof file.filenameIV !== 'string') {
    throw new Error(`File at index ${index} missing required field: filenameIV`);
  }
}

/**
 * Build canonical string for capsa signature.
 * Format: packageId|version|totalSize|algorithm|hashes|(file)iv[s]|filenameIV[s]|structuredIV|subjectIV|bodyIV
 * createdAt excluded because the server sets it when the capsa is stored.
 * @throws Error if validation fails
 */
export function buildCanonicalString(params: {
  packageId: string;
  version?: string;
  totalSize: number;
  algorithm: string;
  files: EncryptedFile[];
  structuredIV?: string;
  subjectIV?: string;
  bodyIV?: string;
}): string {
  if (!params.packageId || typeof params.packageId !== 'string') {
    throw new Error('Invalid canonicalString: packageId must be a non-empty string');
  }
  if (typeof params.totalSize !== 'number' || params.totalSize < 0) {
    throw new Error('Invalid canonicalString: totalSize must be a non-negative number');
  }
  if (!params.algorithm || typeof params.algorithm !== 'string') {
    throw new Error('Invalid canonicalString: algorithm must be a non-empty string');
  }
  if (!Array.isArray(params.files)) {
    throw new Error('Invalid canonicalString: files must be an array');
  }

  params.files.forEach((file, index) => validateEncryptedFile(file, index));

  const version = params.version || '1.0.0';

  const canonicalParts: string[] = [
    params.packageId,
    version,
    String(params.totalSize), // Use String() instead of .toString()
    params.algorithm,
  ];

  // Preserve file order - DO NOT SORT (for deterministic signatures)
  if (params.files.length > 0) {
    const hashes = params.files.map((f) => f.hash);
    const ivs = params.files.map((f) => f.iv);
    const filenameIVs = params.files.map((f) => f.filenameIV);

    canonicalParts.push(...hashes);
    canonicalParts.push(...ivs);
    canonicalParts.push(...filenameIVs);
  }

  // Skip empty/undefined optional IVs
  if (params.structuredIV) {
    canonicalParts.push(params.structuredIV);
  }
  if (params.subjectIV) {
    canonicalParts.push(params.subjectIV);
  }
  if (params.bodyIV) {
    canonicalParts.push(params.bodyIV);
  }

  return canonicalParts.join('|');
}

/**
 * Create JWS capsa signature using RSA-SHA256.
 * @throws Error if key is invalid or signing fails
 */
export function createCapsaSignature(
  canonicalString: string,
  privateKeyPEM: string
): CapsaSignature {
  if (!canonicalString || typeof canonicalString !== 'string') {
    throw new Error('canonicalString must be a non-empty string');
  }
  if (!privateKeyPEM || typeof privateKeyPEM !== 'string') {
    throw new Error('privateKeyPEM must be a non-empty string');
  }

  const joseHeader = {
    alg: 'RS256',
    typ: 'JWT',
  };

  const protectedHeader = Buffer.from(JSON.stringify(joseHeader)).toString(
    'base64url'
  );
  const payload = Buffer.from(canonicalString, 'utf-8').toString('base64url');

  const signingInput = `${protectedHeader}.${payload}`;

  let privateKeyObject: crypto.KeyObject;
  try {
    privateKeyObject = crypto.createPrivateKey({
      key: privateKeyPEM,
      format: 'pem',
    });
  } catch (error) {
    throw new Error(
      `Invalid private key: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }

  const signatureBuffer = crypto.sign(
    'sha256',
    Buffer.from(signingInput, 'utf-8'),
    privateKeyObject
  );

  const signature = signatureBuffer.toString('base64url');

  return {
    algorithm: 'RS256',
    protected: protectedHeader,
    payload,
    signature,
  };
}

/**
 * Verify capsa signature.
 * @returns True if signature is valid, false if it doesn't match
 * @throws Error if inputs are invalid or key errors occur
 */
export function verifyCapsaSignature(
  signature: CapsaSignature,
  canonicalString: string,
  publicKeyPEM: string
): boolean {
  if (!signature || typeof signature !== 'object') {
    throw new Error('signature must be a CapsaSignature object');
  }
  if (!signature.payload || typeof signature.payload !== 'string') {
    throw new Error('signature.payload must be a non-empty string');
  }
  if (!signature.protected || typeof signature.protected !== 'string') {
    throw new Error('signature.protected must be a non-empty string');
  }
  if (!signature.signature || typeof signature.signature !== 'string') {
    throw new Error('signature.signature must be a non-empty string');
  }
  if (!canonicalString || typeof canonicalString !== 'string') {
    throw new Error('canonicalString must be a non-empty string');
  }
  if (!publicKeyPEM || typeof publicKeyPEM !== 'string') {
    throw new Error('publicKeyPEM must be a non-empty string');
  }

  // Constant-time comparison to prevent timing attacks
  const expectedPayload = Buffer.from(canonicalString, 'utf-8').toString('base64url');
  const expectedPayloadBuffer = Buffer.from(expectedPayload, 'utf-8');
  const actualPayloadBuffer = Buffer.from(signature.payload, 'utf-8');

  // Check lengths first (length comparison is not timing-sensitive for this use case)
  if (expectedPayloadBuffer.length !== actualPayloadBuffer.length) {
    return false;
  }

  // Constant-time comparison to prevent timing side-channel attacks
  if (!crypto.timingSafeEqual(expectedPayloadBuffer, actualPayloadBuffer)) {
    return false;
  }

  const signingInput = `${signature.protected}.${signature.payload}`;

  let publicKeyObject: crypto.KeyObject;
  try {
    publicKeyObject = crypto.createPublicKey({
      key: publicKeyPEM,
      format: 'pem',
    });
  } catch (error) {
    throw new Error(
      `Invalid public key: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }

  try {
    return crypto.verify(
      'sha256',
      Buffer.from(signingInput, 'utf-8'),
      publicKeyObject,
      Buffer.from(signature.signature, 'base64url')
    );
  } catch {
    throw new Error('Signature verification failed');
  }
}
