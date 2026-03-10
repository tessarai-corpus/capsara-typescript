/** API error response structure from Axios. */
export interface ApiErrorResponse {
  status: number;
  statusText?: string;
  headers?: Record<string, string>;
  data?: {
    error?: {
      code?: string;
      message?: string;
      details?: Record<string, unknown>;
    };
    message?: string;
    details?: Record<string, unknown>;
  };
}

/** Axios-like error structure. */
export interface AxiosLikeError {
  response?: ApiErrorResponse;
  request?: unknown;
  message?: string;
}

/** Stored response for debugging (subset of ApiErrorResponse). */
export interface StoredErrorResponse {
  status: number;
  statusText?: string;
  headers?: Record<string, string>;
  data?: unknown;
}

/** Base error class for all Capsara SDK errors. */
export class CapsaraError extends Error {
  /** Error code from API response */
  public readonly code: string;

  /** HTTP status code */
  public readonly statusCode: number;

  /** Additional error details */
  public readonly details?: Record<string, unknown>;

  /** Full server response (for debugging) */
  public readonly response?: StoredErrorResponse;

  constructor(
    message: string,
    code: string,
    statusCode: number,
    details?: Record<string, unknown>,
    response?: ApiErrorResponse
  ) {
    super(message);
    this.name = 'CapsaraError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;

    // Store sanitized response for debugging (filter sensitive headers, truncate data)
    if (response) {
      const SAFE_HEADERS = ['content-type', 'x-request-id', 'retry-after'];
      let filteredHeaders: Record<string, string> | undefined;
      if (response.headers) {
        filteredHeaders = {};
        for (const key of Object.keys(response.headers)) {
          if (SAFE_HEADERS.includes(key.toLowerCase())) {
            filteredHeaders[key] = response.headers[key]!;
          }
        }
      }

      // Truncate response data to prevent unbounded memory from large error bodies
      const MAX_DATA_SIZE = 1024;
      let truncatedData: unknown = response.data;
      if (response.data) {
        const serialized = JSON.stringify(response.data);
        if (serialized.length > MAX_DATA_SIZE) {
          truncatedData = serialized.slice(0, MAX_DATA_SIZE) + '...[truncated]';
        }
      }

      this.response = {
        status: response.status,
        statusText: response.statusText,
        headers: filteredHeaders,
        data: truncatedData,
      };
    }

    // Maintains proper stack trace for where error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }

    // Set the prototype explicitly to support instanceof checks
    Object.setPrototypeOf(this, CapsaraError.prototype);
  }

  /** Maps an API error response to a CapsaraError. */
  static fromApiError(error: AxiosLikeError): CapsaraError {
    // Handle axios error structure
    if (error.response) {
      const { data, status } = error.response;
      const errorCode = data?.error?.code ?? 'UNKNOWN_ERROR';
      const errorMessage = data?.error?.message ?? error.message ?? 'An unknown error occurred';
      const errorDetails = data?.error?.details;

      return new CapsaraError(
        errorMessage,
        errorCode,
        status,
        errorDetails,
        error.response // Pass full response for debugging
      );
    }

    // Handle network errors or other errors
    if (error.request) {
      return new CapsaraError(
        'Network error: Unable to reach the API',
        'NETWORK_ERROR',
        0,
        { originalError: error.message ?? 'Unknown network error' }
      );
    }

    // Generic error
    const errorMessage = error.message ?? 'An error occurred';
    return new CapsaraError(
      errorMessage,
      'UNKNOWN_ERROR',
      500,
      { originalError: errorMessage }
    );
  }

  /** Converts this error to a JSON-serializable object. */
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      details: this.details,
      ...(this.response && { response: this.response }),
    };
  }
}
