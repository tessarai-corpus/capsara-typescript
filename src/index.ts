/** Capsara SDK entry point. */

export { CapsaraClient, type CapsaraClientOptions } from './client/capsara-client.js';

export type { CapsaBuilder } from './builder/capsa-builder.js';

export type { HttpTimeoutConfig } from './internal/config/http-client.js';

export type { RetryConfig, RetryLogger } from './internal/config/retry-interceptor.js';

export { type DecryptedCapsa } from './internal/decryptor/capsa-decryptor.js';

export type { SendResult, SendCreated, SendFailure } from './internal/services/upload-service.js';

export type { DecryptedFileResult } from './internal/services/download-service.js';

export { sanitizeFilename } from './internal/utils/safe-filename.js';

export {
  CapsaraError,
  CapsaraAuditError,
  CapsaraCapsaError,
  CapsaraAuthError,
  CapsaraAccountError,
} from './errors/index.js';

export type { ApiErrorResponse, StoredErrorResponse, CapsaraErrorExtras } from './errors/index.js';

export { FileInput } from './types/index.js';

export type {
  PartyKey,
  Capsa,
  CapsaStatus,
  KeychainEntry,
  EncryptedFile,
  CapsaSignature,
  CapsaMetadata,
  BuiltCapsa,
  CapsaUploadData,
  RecipientConfig,
  SystemLimits,
  AuthCredentials,
  AuthResponse,
  CapsaListFilters,
  CapsaListResponse,
  CapsaSummary,
  CursorPagination,
  OffsetPagination,
  AuditEntry,
  AuditAction,
  GetAuditEntriesFilters,
  GetAuditEntriesResponse,
  CreateAuditEntryRequest,
  CreateAuditEntryResponse,
  GeneratedKeyPair,
  PublicKeyInfo,
  KeyHistoryEntry,
  RotateKeyOptions,
} from './types/index.js';
