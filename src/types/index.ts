import { basename } from 'path';

export type {
  KeychainEntry,
  EncryptedFile,
  CapsaSignature,
  CapsaMetadata,
} from '../internal/types.js';

export interface PartyKey {
  id: string;
  email: string;
  publicKey: string;
  fingerprint: string;
  isDelegate?: boolean | string[];
}

export interface Capsa {
  id: string;
  createdAt: string;
  updatedAt: string;
  status: 'active' | 'soft_deleted' | 'expired';
  creator: string;
  signature: {
    algorithm: string;
    protected: string;
    payload: string;
    signature: string;
  };
  keychain: {
    algorithm: string;
    keys: import('../internal/types.js').KeychainEntry[];
  };
  files: import('../internal/types.js').EncryptedFile[];
  encryptedStructured?: string;
  structuredIV?: string;
  structuredAuthTag?: string;
  encryptedSubject?: string;
  subjectIV?: string;
  subjectAuthTag?: string;
  encryptedBody?: string;
  bodyIV?: string;
  bodyAuthTag?: string;
  accessControl: {
    expiresAt?: string;
  };
  metadata?: import('../internal/types.js').CapsaMetadata;
  totalSize: number;
}

export interface FileInput {
  path?: string;
  buffer?: Buffer;
  filename: string;
  mimetype?: string;
  compress?: boolean;
  expiresAt?: string | Date;
  /** One-way transform reference (URL or @partyId/id) */
  transform?: string;
}

// eslint-disable-next-line @typescript-eslint/no-redeclare -- intentional companion object pattern
export const FileInput = {
  fromPath(filePath: string, filename?: string, mimetype?: string): FileInput {
    const resolvedFilename = filename ?? basename(filePath);
    return { path: filePath, filename: resolvedFilename, mimetype };
  },

  fromBuffer(buffer: Buffer, filename: string, mimetype?: string): FileInput {
    return { buffer, filename, mimetype };
  },

  withoutCompression(input: FileInput): FileInput {
    return { ...input, compress: false };
  },

  withExpiration(input: FileInput, expiresAt: Date | string): FileInput {
    return { ...input, expiresAt };
  },

  withMimetype(input: FileInput, mimetype: string): FileInput {
    return { ...input, mimetype };
  },
};

export interface RecipientConfig {
  partyId: string;
  permissions: string[];
  actingFor?: string[];
}

export interface AuthCredentials {
  email: string;
  password: string;
}

export interface AuthResponse {
  party: {
    id: string;
    email: string;
    name: string;
    kind: string;
    publicKey?: string;
    publicKeyFingerprint?: string;
  };
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface SystemLimits {
  maxFileSize: number;
  maxFilesPerCapsa: number;
  maxTotalSize: number;
}

export type { GeneratedKeyPair } from '../internal/crypto/key-generator.js';
export type { PublicKeyInfo, KeyHistoryEntry } from '../internal/services/account-service.js';
export type { BuiltCapsa, CapsaUploadData } from '../builder/capsa-builder.js';

export interface CapsaListFilters {
  status?: 'active' | 'expired';
  createdBy?: string;
  startDate?: string;
  endDate?: string;
  expiringBefore?: string;
  hasLegalHold?: boolean;
  limit?: number;
  after?: string;
  before?: string;
}

export interface CapsaListResponse {
  capsas: CapsaSummary[];
  pagination: CursorPagination;
}

/** Lightweight capsa summary for list responses */
export interface CapsaSummary {
  id: string;
  createdAt: string;
  creator: string;
  status: 'active' | 'soft_deleted' | 'expired';
  expiresAt?: string;
}

export interface CursorPagination {
  limit: number;
  hasMore: boolean;
  nextCursor?: string;
  prevCursor?: string;
}

export interface AuditEntry {
  timestamp: string;
  party: string;
  action: AuditAction;
  ipAddress?: string;
  deviceFingerprint?: string;
  details?: Record<string, unknown>;
}

export type AuditAction =
  | 'created'
  | 'accessed'
  | 'file_downloaded'
  | 'processed'
  | 'expired'
  | 'deleted'
  | 'log';

export interface GetAuditEntriesFilters {
  action?: string;
  party?: string;
  page?: number;
  limit?: number;
}

export interface GetAuditEntriesResponse {
  auditEntries: AuditEntry[];
  pagination: CursorPagination;
}

export interface CreateAuditEntryRequest {
  action: 'log' | 'processed';
  details?: Record<string, unknown>;
}

export interface CreateAuditEntryResponse {
  success: boolean;
}
