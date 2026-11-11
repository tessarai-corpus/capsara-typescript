/** Errors from account operations (keys, key history). */

import {
  CapsaraError,
  parseApiError,
  type ApiErrorResponse,
  type CapsaraErrorExtras,
} from './capsara-error.js';
import { CapsaraAuthError } from './auth-error.js';

export class CapsaraAccountError extends CapsaraError {
  constructor(
    message: string,
    code: string,
    statusCode: number,
    details?: unknown,
    response?: ApiErrorResponse,
    extras?: CapsaraErrorExtras
  ) {
    super(message, code, statusCode, details, response, extras);
    this.name = 'CapsaraAccountError';
  }

  static fromApiError(error: unknown): CapsaraAccountError | CapsaraAuthError {
    if (error instanceof CapsaraAccountError || error instanceof CapsaraAuthError) {
      return error;
    }
    const parsed = parseApiError(error, 'ACCOUNT_ERROR');
    return new CapsaraAccountError(parsed.message, parsed.code, parsed.statusCode, parsed.details, parsed.response, parsed);
  }
}
