/** Errors from authentication operations (login, register, refresh). */

import { CapsaraError, type ApiErrorResponse, type AxiosLikeError } from './capsara-error.js';

export class CapsaraAuthError extends CapsaraError {
  constructor(
    message: string,
    code: string,
    statusCode: number,
    details?: Record<string, unknown>,
    response?: ApiErrorResponse
  ) {
    super(message, code, statusCode, details, response);
    this.name = 'CapsaraAuthError';
  }

  /**
   * Refresh token is required but not provided
   * HTTP 401 - REFRESH_TOKEN_REQUIRED
   */
  static refreshTokenRequired(): CapsaraAuthError {
    return new CapsaraAuthError(
      'Refresh token is required',
      'REFRESH_TOKEN_REQUIRED',
      401
    );
  }

  /**
   * Invalid credentials (email/password don't match)
   * HTTP 401 - INVALID_CREDENTIALS
   */
  static invalidCredentials(): CapsaraAuthError {
    return new CapsaraAuthError(
      'Invalid email or password',
      'INVALID_CREDENTIALS',
      401
    );
  }

  /**
   * Refresh token is invalid or expired
   * HTTP 401 - INVALID_REFRESH_TOKEN
   */
  static invalidRefreshToken(): CapsaraAuthError {
    return new CapsaraAuthError(
      'Refresh token is invalid or expired',
      'INVALID_REFRESH_TOKEN',
      401
    );
  }

  /**
   * Access token is invalid or expired
   * HTTP 401 - UNAUTHORIZED
   */
  static unauthorized(message = 'Unauthorized - invalid or expired access token'): CapsaraAuthError {
    return new CapsaraAuthError(
      message,
      'UNAUTHORIZED',
      401
    );
  }

  /**
   * Feature not implemented yet
   * HTTP 405 - NOT_IMPLEMENTED
   */
  static notImplemented(feature: string): CapsaraAuthError {
    return new CapsaraAuthError(
      `${feature} endpoint not yet implemented`,
      'NOT_IMPLEMENTED',
      405,
      { feature }
    );
  }

  /**
   * Invalid request body
   * HTTP 400 - VALIDATION_ERROR
   */
  static validationError(message: string, details?: Record<string, unknown>): CapsaraAuthError {
    return new CapsaraAuthError(
      message,
      'VALIDATION_ERROR',
      400,
      details
    );
  }

  /** Maps an API error response to the appropriate factory method. */
  static fromApiError(error: AxiosLikeError): CapsaraAuthError {
    // Handle axios errors
    if (error.response) {
      const status = error.response.status;
      const data = error.response.data;
      const errorCode = data?.error?.code;
      const errorMessage = data?.error?.message ?? data?.message ?? error.message ?? 'Unknown error';
      const errorDetails = data?.error?.details ?? data?.details;

      // Map known error codes to factory methods
      switch (errorCode) {
        case 'REFRESH_TOKEN_REQUIRED':
          return CapsaraAuthError.refreshTokenRequired();

        case 'INVALID_CREDENTIALS':
          return CapsaraAuthError.invalidCredentials();

        case 'INVALID_REFRESH_TOKEN':
          return CapsaraAuthError.invalidRefreshToken();

        case 'UNAUTHORIZED':
          return CapsaraAuthError.unauthorized(errorMessage);

        case 'NOT_IMPLEMENTED':
          return CapsaraAuthError.notImplemented((errorDetails?.feature as string) ?? 'Feature');

        case 'VALIDATION_ERROR':
          return CapsaraAuthError.validationError(errorMessage, errorDetails);

        default:
          // Generic auth error with status code
          return new CapsaraAuthError(
            errorMessage,
            errorCode ?? 'AUTH_ERROR',
            status,
            errorDetails
          );
      }
    }

    // Handle non-axios errors
    if (error instanceof CapsaraAuthError) {
      return error;
    }

    // Generic error fallback
    const errorMessage = error.message ?? 'Unknown authentication error';
    return new CapsaraAuthError(
      errorMessage,
      'AUTH_ERROR',
      500,
      { originalError: errorMessage }
    );
  }
}
