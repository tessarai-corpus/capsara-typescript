/** Errors from audit trail operations. */

import {
  CapsaraError,
  parseApiError,
  type ApiErrorResponse,
  type CapsaraErrorExtras,
  type StoredErrorResponse,
} from './capsara-error.js';
import { CapsaraAuthError } from './auth-error.js';

export class CapsaraAuditError extends CapsaraError {
  declare public readonly response?: StoredErrorResponse;

  constructor(
    message: string,
    code: string,
    statusCode: number,
    details?: unknown,
    response?: ApiErrorResponse,
    extras?: CapsaraErrorExtras
  ) {
    super(message, code, statusCode, details, response, extras);
    this.name = 'CapsaraAuditError';
  }

  static missingDetails(): CapsaraAuditError {
    return new CapsaraAuditError(
      'Details field is required for log action',
      'MISSING_DETAILS',
      0
    );
  }

  static fromApiError(error: unknown): CapsaraAuditError | CapsaraAuthError {
    if (error instanceof CapsaraAuditError || error instanceof CapsaraAuthError) {
      return error;
    }
    const parsed = parseApiError(error, 'AUDIT_ERROR');
    return new CapsaraAuditError(parsed.message, parsed.code, parsed.statusCode, parsed.details, parsed.response, parsed);
  }
}
