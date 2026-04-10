/** Internal types used by services, builders, and crypto modules. */

export interface KeychainEntry {
  party: string;
  encryptedKey: string;
  iv: string;
  fingerprint: string;
  permissions: string[];
  actingFor?: string[];  // Array of party IDs this delegate represents
  revoked?: boolean;
}

/** Matches API response. */
export interface EncryptedFile {
  fileId: string;
  encryptedFilename: string;
  filenameIV: string;
  filenameAuthTag: string;
  iv: string;
  authTag: string;
  mimetype: string;
  size: number;
  hash: string;
  hashAlgorithm: string;
  expiresAt?: string; // Optional file-level expiration (ISO 8601 UTC)
  // Compression metadata (set if file was compressed before encryption)
  compressed?: boolean;
  compressionAlgorithm?: 'gzip';
  originalSize?: number;
  /** One-way transform reference (URL or @partyId/id) */
  transform?: string;
}

export interface FileEncryptionResult {
  encryptedData: Buffer;
  iv: string;
  authTag: string;
  hash: string;
  size: number;
  mimetype: string;
  compressed?: boolean;
  compressionAlgorithm?: 'gzip';
  originalSize?: number;
}

export interface CapsaSignature {
  algorithm: string;
  protected: string;
  payload: string;
  signature: string;
}

/**
 * Unencrypted metadata visible to server.
 * Only non-sensitive operational data for routing, display, and search.
 */
export interface CapsaMetadata {
  label?: string;
  relatedPackages?: string[];
  tags?: string[];
  notes?: string;
}

export interface CapsaCreateOptions {
  subject?: string;
  body?: string;
  structured?: Record<string, unknown>;
  expiresAt?: string;
}

export interface AESEncryptionResult {
  encryptedData: string;
  iv: string;
  authTag: string;
}

export interface MultipartPart {
  name: string;
  content: string | Buffer;
  contentType?: string;
  filename?: string;
}
