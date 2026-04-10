/** Re-exports all SDK error classes and types. */

export { CapsaraError } from './capsara-error.js';
export { CapsaraAuditError } from './audit-error.js';
export { CapsaraCapsaError } from './capsa-error.js';
export { CapsaraAuthError } from './auth-error.js';
export { CapsaraAccountError } from './account-error.js';

// Re-export types for convenience
export type { ApiErrorResponse, AxiosLikeError, StoredErrorResponse } from './capsara-error.js';
