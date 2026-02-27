/** Errors from capsa operations (create, get, delete, file operations). */

import { CapsaraError, type ApiErrorResponse, type AxiosLikeError, type StoredErrorResponse } from './capsara-error.js';

export class CapsaraCapsaError extends CapsaraError {
  declare public readonly response?: StoredErrorResponse;

  constructor(
    message: string,
    code: string,
    statusCode: number,
    details?: Record<string, unknown>,
    response?: ApiErrorResponse
  ) {
    super(message, code, statusCode, details, response);
    this.name = 'CapsaraCapsaError';
  }

  /**
   * Capsa not found or access denied
   * HTTP 404 - CAPSA_NOT_FOUND
   */
  static capsaNotFound(capsaId?: string): CapsaraCapsaError {
    return new CapsaraCapsaError(
      capsaId
        ? `Capsa with ID ${capsaId} not found or access denied`
        : 'Capsa not found or access denied',
      'CAPSA_NOT_FOUND',
      404,
      capsaId ? { capsaId } : undefined
    );
  }

  /**
   * File not found in capsa
   * HTTP 404 - FILE_NOT_FOUND
   */
  static fileNotFound(fileId?: string): CapsaraCapsaError {
    return new CapsaraCapsaError(
      'File not found in capsa',
      'FILE_NOT_FOUND',
      404,
      fileId ? { fileId } : undefined
    );
  }

  /**
   * Access denied to capsa
   * HTTP 403 - ACCESS_DENIED
   */
  static accessDenied(details?: Record<string, unknown>): CapsaraCapsaError {
    return new CapsaraCapsaError(
      'You do not have access to this capsa',
      'ACCESS_DENIED',
      403,
      details
    );
  }

  /**
   * Creator mismatch - authenticated party doesn't match creator in metadata
   * HTTP 403 - CREATOR_MISMATCH
   */
  static creatorMismatch(authenticated: string, claimed: string): CapsaraCapsaError {
    return new CapsaraCapsaError(
      'Authenticated party does not match creator in metadata',
      'CREATOR_MISMATCH',
      403,
      { authenticated, claimed }
    );
  }

  /**
   * Capsa is deleted and cannot be accessed
   * HTTP 403 - CAPSA_DELETED
   */
  static capsaDeleted(details?: Record<string, unknown>): CapsaraCapsaError {
    return new CapsaraCapsaError(
      'Cannot download files from deleted capsa',
      'CAPSA_DELETED',
      403,
      details
    );
  }

  /**
   * Invalid content type - must be multipart/form-data
   * HTTP 400 - INVALID_CONTENT_TYPE
   */
  static invalidContentType(): CapsaraCapsaError {
    return new CapsaraCapsaError(
      'Request must be multipart/form-data with metadata and capsa_0..N fields',
      'INVALID_CONTENT_TYPE',
      400
    );
  }

  /**
   * Missing required parameters
   * HTTP 400 - MISSING_PARAMS
   */
  static missingParams(params?: string[]): CapsaraCapsaError {
    return new CapsaraCapsaError(
      params
        ? `Missing required parameters: ${params.join(', ')}`
        : 'Missing required parameters',
      'MISSING_PARAMS',
      400,
      params ? { missingParams: params } : undefined
    );
  }

  /**
   * Missing capsa ID
   * HTTP 400 - MISSING_ID
   */
  static missingId(): CapsaraCapsaError {
    return new CapsaraCapsaError(
      'Capsa ID is required',
      'MISSING_ID',
      400
    );
  }

  /**
   * Invalid expiration time for download URL
   * HTTP 400 - INVALID_EXPIRATION
   */
  static invalidExpiration(): CapsaraCapsaError {
    return new CapsaraCapsaError(
      'URL expiration must be between 1 and 1440 minutes (24 hours)',
      'INVALID_EXPIRATION',
      400
    );
  }

  /**
   * Multipart upload error (file size, count, etc.)
   * HTTP 400/413 - MULTIPART_ERROR
   */
  static multipartError(message: string, statusCode = 400, details?: Record<string, unknown>): CapsaraCapsaError {
    return new CapsaraCapsaError(
      message,
      'MULTIPART_ERROR',
      statusCode,
      details
    );
  }

  /**
   * File download failed with context
   * Used to wrap errors with capsaId and fileId context
   */
  static downloadFailed(
    capsaId: string,
    fileId: string,
    cause: unknown
  ): CapsaraCapsaError {
    const causeMessage = cause instanceof Error ? cause.message : String(cause);
    const error = new CapsaraCapsaError(
      `Failed to download file ${fileId} from capsa ${capsaId}: ${causeMessage}`,
      'DOWNLOAD_FAILED',
      0, // Status 0 indicates client-side error
      { capsaId, fileId, originalError: causeMessage }
    );
    // Preserve the original error as cause for stack trace
    if (cause instanceof Error) {
      error.cause = cause;
    }
    return error;
  }

  /** Maps an API error response to the appropriate factory method. */
  static fromApiError(error: AxiosLikeError): CapsaraCapsaError {
    // Handle axios errors
    if (error.response) {
      const status = error.response.status;
      const data = error.response.data;
      const errorCode = data?.error?.code;
      const errorMessage = data?.error?.message ?? data?.message ?? error.message ?? 'Unknown error';
      const errorDetails = data?.error?.details ?? data?.details;
      const response = error.response;

      // Map known error codes to factory methods and attach response
      let capsaError: CapsaraCapsaError;

      switch (errorCode) {
        // Support both old ENVELOPE_* and new CAPSA_* error codes from API
        case 'ENVELOPE_NOT_FOUND':
        case 'CAPSA_NOT_FOUND':
          capsaError = CapsaraCapsaError.capsaNotFound(
            (errorDetails?.capsaId ?? errorDetails?.envelopeId) as string | undefined
          );
          break;
        case 'FILE_NOT_FOUND':
          capsaError = CapsaraCapsaError.fileNotFound(errorDetails?.fileId as string | undefined);
          break;
        case 'ACCESS_DENIED':
          capsaError = CapsaraCapsaError.accessDenied(errorDetails);
          break;
        case 'CREATOR_MISMATCH':
          capsaError = CapsaraCapsaError.creatorMismatch(
            (errorDetails?.authenticated as string) ?? '',
            (errorDetails?.claimed as string) ?? ''
          );
          break;
        case 'ENVELOPE_DELETED':
        case 'CAPSA_DELETED':
          capsaError = CapsaraCapsaError.capsaDeleted(errorDetails);
          break;
        case 'INVALID_CONTENT_TYPE':
          capsaError = CapsaraCapsaError.invalidContentType();
          break;
        case 'MISSING_PARAMS':
          capsaError = CapsaraCapsaError.missingParams(errorDetails?.missingParams as string[] | undefined);
          break;
        case 'MISSING_ID':
          capsaError = CapsaraCapsaError.missingId();
          break;
        case 'INVALID_EXPIRATION':
          capsaError = CapsaraCapsaError.invalidExpiration();
          break;
        case 'MULTIPART_ERROR':
          capsaError = CapsaraCapsaError.multipartError(errorMessage, status, errorDetails);
          break;
        default:
          // Generic capsa error with status code
          return new CapsaraCapsaError(
            errorMessage,
            errorCode ?? 'CAPSA_ERROR',
            status,
            errorDetails,
            response
          );
      }

      // Attach response to error created by factory method
      if (response) {
        Object.defineProperty(capsaError, 'response', {
          value: {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
            data: response.data,
          },
          writable: false,
          enumerable: true,
          configurable: true,
        });
      }

      return capsaError;
    }

    // Handle non-axios errors
    if (error instanceof CapsaraCapsaError) {
      return error;
    }

    // Generic error fallback (client-side errors, not API errors)
    // Use status code 0 to distinguish from actual HTTP 500 errors
    const errorMessage = error.message ?? 'Unknown capsa error';
    return new CapsaraCapsaError(
      errorMessage,
      'CAPSA_ERROR',
      0,
      { originalError: errorMessage }
    );
  }
}
