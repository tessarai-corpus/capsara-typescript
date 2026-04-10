import { CapsaraError, type ApiErrorResponse, type AxiosLikeError, type StoredErrorResponse } from './capsara-error.js';

/** Errors from audit trail operations. */
export class CapsaraAuditError extends CapsaraError {
  declare public readonly response?: StoredErrorResponse;

  constructor(
    message: string,
    code: string,
    statusCode: number,
    details?: Record<string, unknown>,
    response?: ApiErrorResponse
  ) {
    super(message, code, statusCode, details, response);
    this.name = 'CapsaraAuditError';
    Object.setPrototypeOf(this, CapsaraAuditError.prototype);
  }

  /**
   * Create error for insufficient permissions
   * Thrown when recipient tries to add 'log' action (creator-only)
   */
  static insufficientPermissions(details?: Record<string, unknown>): CapsaraAuditError {
    return new CapsaraAuditError(
      'You do not have permission to perform this action',
      'INSUFFICIENT_PERMISSIONS',
      403,
      details
    );
  }

  /**
   * Create error for invalid audit action
   * Thrown when action is not 'log' or 'processed'
   */
  static invalidAction(action?: string): CapsaraAuditError {
    return new CapsaraAuditError(
      'Invalid audit action',
      'INVALID_AUDIT_ACTION',
      400,
      { action }
    );
  }

  /**
   * Create error for access denied
   * Thrown when party is not in capsa keychain
   */
  static accessDenied(details?: Record<string, unknown>): CapsaraAuditError {
    return new CapsaraAuditError(
      'You do not have access to this capsa',
      'ACCESS_DENIED',
      403,
      details
    );
  }

  /**
   * Create error for missing details field
   * Thrown when 'log' action is used without details
   */
  static missingDetails(): CapsaraAuditError {
    return new CapsaraAuditError(
      'Details field is required for log action',
      'MISSING_DETAILS',
      400
    );
  }

  /**
   * Create error for capsa not found
   * Thrown when capsa doesn't exist
   */
  static capsaNotFound(capsaId: string): CapsaraAuditError {
    return new CapsaraAuditError(
      'Capsa not found or access denied',
      'CAPSA_NOT_FOUND',
      404,
      { capsaId }
    );
  }

  /** Maps an API error response to the appropriate factory method. */
  static fromApiError(error: AxiosLikeError): CapsaraAuditError {
    // Extract error information
    const errorCode = error.response?.data?.error?.code;
    const errorMessage = error.response?.data?.error?.message;
    const statusCode = error.response?.status ?? 500;
    const details = error.response?.data?.error?.details;
    const response = error.response;

    // Map known error codes to factory methods
    // Note: Factory methods don't include response, so add it after creation
    let auditError: CapsaraAuditError;

    switch (errorCode) {
      case 'INSUFFICIENT_PERMISSIONS':
        auditError = CapsaraAuditError.insufficientPermissions(details);
        break;
      case 'INVALID_AUDIT_ACTION':
        auditError = CapsaraAuditError.invalidAction(details?.action as string | undefined);
        break;
      case 'ACCESS_DENIED':
        auditError = CapsaraAuditError.accessDenied(details);
        break;
      case 'MISSING_DETAILS':
        auditError = CapsaraAuditError.missingDetails();
        break;
      case 'ENVELOPE_NOT_FOUND':
      case 'CAPSA_NOT_FOUND':
        auditError = CapsaraAuditError.capsaNotFound(
          ((details?.capsaId ?? details?.envelopeId) as string) ?? ''
        );
        break;
      default:
        // Generic audit error for unknown codes
        return new CapsaraAuditError(
          errorMessage ?? 'An audit error occurred',
          errorCode ?? 'UNKNOWN_AUDIT_ERROR',
          statusCode,
          details,
          response
        );
    }

    // Add response to error created by factory method
    if (response) {
      Object.defineProperty(auditError, 'response', {
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

    return auditError;
  }
}
