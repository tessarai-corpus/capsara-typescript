/** Errors from authentication operations (login, refresh). */

import {
  CapsaraError,
  parseApiError,
  type ApiErrorResponse,
  type CapsaraErrorExtras,
} from './capsara-error.js';

export class CapsaraAuthError extends CapsaraError {
  constructor(
    message: string,
    code: string,
    statusCode: number,
    details?: unknown,
    response?: ApiErrorResponse,
    extras?: CapsaraErrorExtras
  ) {
    super(message, code, statusCode, details, response, extras);
    this.name = 'CapsaraAuthError';
  }

  static fromApiError(error: unknown): CapsaraAuthError {
    if (error instanceof CapsaraAuthError) {
      return error;
    }
    const parsed = parseApiError(error, 'AUTH_ERROR');
    return new CapsaraAuthError(parsed.message, parsed.code, parsed.statusCode, parsed.details, parsed.response, parsed);
  }
}
