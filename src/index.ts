/** Capsara SDK entry point. */

export { CapsaraClient, type CapsaraClientOptions } from './client/capsara-client.js';

export { type DecryptedCapsa } from './internal/decryptor/capsa-decryptor.js';

export {
  CapsaraError,
  CapsaraAuditError,
  CapsaraCapsaError,
  CapsaraAuthError,
  CapsaraAccountError,
} from './errors/index.js';

export { FileInput } from './types/index.js';

export type {
  PartyKey,
  Capsa,
  RecipientConfig,
  SystemLimits,
  AuthCredentials,
  AuthResponse,
  CapsaListFilters,
  CapsaListResponse,
  CapsaSummary,
  CursorPagination,
  AuditEntry,
  AuditAction,
  GetAuditEntriesFilters,
  GetAuditEntriesResponse,
  CreateAuditEntryRequest,
  CreateAuditEntryResponse,
} from './types/index.js';
