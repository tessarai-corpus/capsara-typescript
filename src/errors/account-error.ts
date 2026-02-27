/** Errors from account operations (webhooks, keys, licenses, appointments, delegates). */

import { CapsaraError, type ApiErrorResponse, type AxiosLikeError } from './capsara-error.js';

export class CapsaraAccountError extends CapsaraError {
  constructor(
    message: string,
    code: string,
    statusCode: number,
    details?: Record<string, unknown>,
    response?: ApiErrorResponse
  ) {
    super(message, code, statusCode, details, response);
    this.name = 'CapsaraAccountError';
  }

  /**
   * Unauthorized - missing or invalid authentication
   * HTTP 401 - UNAUTHORIZED
   */
  static unauthorized(): CapsaraAccountError {
    return new CapsaraAccountError(
      'Unauthorized',
      'UNAUTHORIZED',
      401
    );
  }

  /**
   * Resource not found (webhook, license, appointment, etc.)
   * HTTP 404 - NOT_FOUND
   */
  static notFound(resourceType: string, identifier?: string): CapsaraAccountError {
    return new CapsaraAccountError(
      identifier
        ? `${resourceType} with identifier ${identifier} not found`
        : `${resourceType} not found`,
      'NOT_FOUND',
      404,
      { resourceType, identifier }
    );
  }

  /**
   * Webhook not found
   * HTTP 404 - WEBHOOK_NOT_FOUND
   */
  static webhookNotFound(webhookId?: string): CapsaraAccountError {
    return CapsaraAccountError.notFound('Webhook', webhookId);
  }

  /**
   * License not found
   * HTTP 404 - LICENSE_NOT_FOUND
   */
  static licenseNotFound(state?: string, licenseNumber?: string): CapsaraAccountError {
    const identifier = state && licenseNumber ? `${state}/${licenseNumber}` : undefined;
    return CapsaraAccountError.notFound('License', identifier);
  }

  /**
   * Appointment not found
   * HTTP 404 - APPOINTMENT_NOT_FOUND
   */
  static appointmentNotFound(carrierPartyId?: string): CapsaraAccountError {
    return CapsaraAccountError.notFound('Appointment', carrierPartyId);
  }

  /**
   * Delegate not found
   * HTTP 404 - DELEGATE_NOT_FOUND
   */
  static delegateNotFound(delegateId?: string): CapsaraAccountError {
    return CapsaraAccountError.notFound('Delegate', delegateId);
  }

  /**
   * Key not found
   * HTTP 404 - KEY_NOT_FOUND
   */
  static keyNotFound(keyFingerprint?: string): CapsaraAccountError {
    return CapsaraAccountError.notFound('Key', keyFingerprint);
  }

  /**
   * Invalid request body (validation error)
   * HTTP 400 - VALIDATION_ERROR
   */
  static validationError(message: string, details?: Record<string, unknown>): CapsaraAccountError {
    return new CapsaraAccountError(
      message || 'Invalid request body',
      'VALIDATION_ERROR',
      400,
      details
    );
  }

  /**
   * Missing required parameter
   * HTTP 400 - MISSING_PARAM
   */
  static missingParam(paramName: string): CapsaraAccountError {
    return new CapsaraAccountError(
      `${paramName} is required`,
      'MISSING_PARAM',
      400,
      { paramName }
    );
  }

  /**
   * Resource already exists (duplicate)
   * HTTP 409 - ALREADY_EXISTS
   */
  static alreadyExists(resourceType: string, identifier?: string): CapsaraAccountError {
    return new CapsaraAccountError(
      identifier
        ? `${resourceType} with identifier ${identifier} already exists`
        : `${resourceType} already exists`,
      'ALREADY_EXISTS',
      409,
      { resourceType, identifier }
    );
  }

  /**
   * Cannot delete active key
   * HTTP 400 - CANNOT_DELETE_ACTIVE_KEY
   */
  static cannotDeleteActiveKey(): CapsaraAccountError {
    return new CapsaraAccountError(
      'Cannot delete the currently active key',
      'CANNOT_DELETE_ACTIVE_KEY',
      400
    );
  }

  /**
   * Webhook limit exceeded
   * HTTP 400 - WEBHOOK_LIMIT_EXCEEDED
   */
  static webhookLimitExceeded(limit: number): CapsaraAccountError {
    return new CapsaraAccountError(
      `Webhook limit of ${limit} exceeded`,
      'WEBHOOK_LIMIT_EXCEEDED',
      400,
      { limit }
    );
  }

  /**
   * Invalid webhook URL
   * HTTP 400 - INVALID_WEBHOOK_URL
   */
  static invalidWebhookUrl(url?: string): CapsaraAccountError {
    return new CapsaraAccountError(
      'Invalid webhook URL',
      'INVALID_WEBHOOK_URL',
      400,
      url ? { url } : undefined
    );
  }

  /** Maps an API error response to the appropriate factory method. */
  static fromApiError(error: AxiosLikeError): CapsaraAccountError {
    // Handle axios errors
    if (error.response) {
      const status = error.response.status;
      const data = error.response.data;
      const errorCode = data?.error?.code;
      const errorMessage = data?.error?.message ?? data?.message ?? error.message ?? 'Unknown error';
      const errorDetails = data?.error?.details ?? data?.details;

      // Map known error codes to factory methods
      switch (errorCode) {
        case 'UNAUTHORIZED':
          return CapsaraAccountError.unauthorized();

        case 'WEBHOOK_NOT_FOUND':
          return CapsaraAccountError.webhookNotFound(
            (errorDetails?.webhookId ?? errorDetails?.identifier) as string | undefined
          );

        case 'LICENSE_NOT_FOUND':
          return CapsaraAccountError.licenseNotFound(
            errorDetails?.state as string | undefined,
            errorDetails?.licenseNumber as string | undefined
          );

        case 'APPOINTMENT_NOT_FOUND':
          return CapsaraAccountError.appointmentNotFound(
            (errorDetails?.carrierPartyId ?? errorDetails?.identifier) as string | undefined
          );

        case 'DELEGATE_NOT_FOUND':
          return CapsaraAccountError.delegateNotFound(
            (errorDetails?.delegateId ?? errorDetails?.identifier) as string | undefined
          );

        case 'KEY_NOT_FOUND':
          return CapsaraAccountError.keyNotFound(
            (errorDetails?.keyFingerprint ?? errorDetails?.identifier) as string | undefined
          );

        case 'NOT_FOUND':
          return CapsaraAccountError.notFound(
            (errorDetails?.resourceType as string) ?? 'Resource',
            errorDetails?.identifier as string | undefined
          );

        case 'VALIDATION_ERROR':
          return CapsaraAccountError.validationError(errorMessage, errorDetails);

        case 'MISSING_PARAM':
          return CapsaraAccountError.missingParam((errorDetails?.paramName as string) ?? 'Parameter');

        case 'ALREADY_EXISTS':
          return CapsaraAccountError.alreadyExists(
            (errorDetails?.resourceType as string) ?? 'Resource',
            errorDetails?.identifier as string | undefined
          );

        case 'CANNOT_DELETE_ACTIVE_KEY':
          return CapsaraAccountError.cannotDeleteActiveKey();

        case 'WEBHOOK_LIMIT_EXCEEDED':
          return CapsaraAccountError.webhookLimitExceeded((errorDetails?.limit as number) ?? 10);

        case 'INVALID_WEBHOOK_URL':
          return CapsaraAccountError.invalidWebhookUrl(errorDetails?.url as string | undefined);

        default:
          // Generic account error with status code
          return new CapsaraAccountError(
            errorMessage,
            errorCode ?? 'ACCOUNT_ERROR',
            status,
            errorDetails
          );
      }
    }

    // Handle non-axios errors
    if (error instanceof CapsaraAccountError) {
      return error;
    }

    // Generic error fallback
    const errorMessage = error.message ?? 'Unknown account error';
    return new CapsaraAccountError(
      errorMessage,
      'ACCOUNT_ERROR',
      500,
      { originalError: errorMessage }
    );
  }
}
