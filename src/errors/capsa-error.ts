/** Errors from capsa operations (create, get, delete, file operations, decryption). */

import {
  CapsaraError,
  parseApiError,
  type ApiErrorResponse,
  type CapsaraErrorExtras,
  type StoredErrorResponse,
} from './capsara-error.js';
import { CapsaraAuthError } from './auth-error.js';

export class CapsaraCapsaError extends CapsaraError {
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
    this.name = 'CapsaraCapsaError';
  }

  static downloadFailed(
    capsaId: string,
    fileId: string,
    cause: unknown
  ): CapsaraCapsaError {
    const causeMessage = cause instanceof Error ? cause.message : String(cause);
    const error = new CapsaraCapsaError(
      `Failed to download file ${fileId} from capsa ${capsaId}: ${causeMessage}`,
      'DOWNLOAD_FAILED',
      0,
      { capsaId, fileId, originalError: causeMessage }
    );
    if (cause instanceof Error) {
      error.cause = cause;
    }
    return error;
  }

  static fromApiError(error: unknown): CapsaraCapsaError | CapsaraAuthError {
    if (error instanceof CapsaraCapsaError || error instanceof CapsaraAuthError) {
      return error;
    }
    const parsed = parseApiError(error, 'CAPSA_ERROR');
    return new CapsaraCapsaError(parsed.message, parsed.code, parsed.statusCode, parsed.details, parsed.response, parsed);
  }
}
