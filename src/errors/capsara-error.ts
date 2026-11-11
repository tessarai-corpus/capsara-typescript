/** Base SDK error and the shared parser for API error responses. */

import { STATUS_CODES } from 'http';

export interface ApiErrorResponse {
  status: number;
  statusText?: string;
  headers?: Record<string, unknown>;
  data?: unknown;
}

export interface AxiosLikeError {
  response?: ApiErrorResponse;
  request?: unknown;
  message?: string;
}

export interface StoredErrorResponse {
  status: number;
  statusText?: string;
  headers?: Record<string, string>;
  data?: unknown;
}

export interface CapsaraErrorExtras {
  retryAfter?: number;
  requestId?: string;
}

export interface ParsedApiError extends CapsaraErrorExtras {
  message: string;
  code: string;
  statusCode: number;
  details?: unknown;
  response?: ApiErrorResponse;
}

const SAFE_HEADERS = ['content-type', 'x-request-id', 'retry-after'];
const MAX_DATA_SIZE = 1024;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function decodeBody(data: unknown): unknown {
  let text: string | undefined;
  if (typeof data === 'string') {
    text = data;
  } else if (Buffer.isBuffer(data)) {
    text = data.toString('utf-8');
  } else if (data instanceof ArrayBuffer) {
    text = Buffer.from(data).toString('utf-8');
  }
  if (text === undefined) {
    return data;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function readHeader(headers: Record<string, unknown> | undefined, name: string): unknown {
  if (!headers) return undefined;
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === name) {
      return headers[key];
    }
  }
  return undefined;
}

function toSeconds(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
    return value;
  }
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    return Number(value.trim());
  }
  return undefined;
}

function reasonPhrase(status: number, statusText?: string): string {
  if (statusText) return statusText;
  return STATUS_CODES[status] ?? `HTTP ${status}`;
}

export function parseErrorResponse(response: ApiErrorResponse): ParsedApiError {
  const status = response.status;
  const body = decodeBody(response.data);
  const errorObject = isRecord(body) && isRecord(body.error) ? body.error : undefined;

  const code = typeof errorObject?.code === 'string' && errorObject.code ? errorObject.code : undefined;
  const parsed: ParsedApiError = code
    ? {
        code,
        message:
          typeof errorObject?.message === 'string' && errorObject.message
            ? errorObject.message
            : reasonPhrase(status, response.statusText),
        statusCode: status,
        details: errorObject?.details,
      }
    : {
        code: `HTTP_${status}`,
        message: reasonPhrase(status, response.statusText),
        statusCode: status,
      };

  const retryAfter = toSeconds(errorObject?.retryAfter) ?? toSeconds(readHeader(response.headers, 'retry-after'));
  if (retryAfter !== undefined) {
    parsed.retryAfter = retryAfter;
  }

  const requestId = errorObject?.requestId ?? (isRecord(body) ? body.requestId : undefined);
  if (typeof requestId === 'string') {
    parsed.requestId = requestId;
  }

  parsed.response = { ...response, data: body };
  return parsed;
}

export function parseApiError(error: unknown, fallbackCode: string): ParsedApiError {
  if (error instanceof CapsaraError) {
    return {
      message: error.message,
      code: error.code,
      statusCode: error.statusCode,
      details: error.details,
      ...(error.retryAfter !== undefined && { retryAfter: error.retryAfter }),
      ...(error.requestId !== undefined && { requestId: error.requestId }),
    };
  }

  const candidate = (isRecord(error) || error instanceof Error ? error : {}) as AxiosLikeError;

  if (candidate.response && typeof candidate.response.status === 'number') {
    return parseErrorResponse(candidate.response);
  }

  const originalMessage = typeof candidate.message === 'string' && candidate.message
    ? candidate.message
    : typeof error === 'string' ? error : undefined;

  if (candidate.request) {
    return {
      message: 'Network error: Unable to reach the API',
      code: 'NETWORK_ERROR',
      statusCode: 0,
      details: { originalError: originalMessage ?? 'Unknown network error' },
    };
  }

  return {
    message: originalMessage ?? 'An unknown error occurred',
    code: fallbackCode,
    statusCode: 0,
    details: { originalError: originalMessage ?? 'Unknown error' },
  };
}

export class CapsaraError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly details?: unknown;
  public readonly retryAfter?: number;
  public readonly requestId?: string;
  public readonly response?: StoredErrorResponse;

  constructor(
    message: string,
    code: string,
    statusCode: number,
    details?: unknown,
    response?: ApiErrorResponse,
    extras?: CapsaraErrorExtras
  ) {
    super(message);
    this.name = 'CapsaraError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    if (extras?.retryAfter !== undefined) {
      this.retryAfter = extras.retryAfter;
    }
    if (extras?.requestId !== undefined) {
      this.requestId = extras.requestId;
    }

    if (response) {
      let filteredHeaders: Record<string, string> | undefined;
      if (response.headers) {
        filteredHeaders = {};
        for (const key of Object.keys(response.headers)) {
          const value = response.headers[key];
          if (SAFE_HEADERS.includes(key.toLowerCase())) {
            if (typeof value === 'string') {
              filteredHeaders[key] = value;
            } else if (typeof value === 'number' || Array.isArray(value)) {
              filteredHeaders[key] = Array.isArray(value) ? value.join(', ') : String(value);
            }
          }
        }
      }

      let truncatedData: unknown = response.data;
      if (response.data !== undefined && response.data !== null) {
        const serialized = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        if (serialized !== undefined && serialized.length > MAX_DATA_SIZE) {
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

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }

    Object.setPrototypeOf(this, new.target.prototype);
  }

  static fromApiError(error: unknown): CapsaraError {
    if (error instanceof CapsaraError) {
      return error;
    }
    const parsed = parseApiError(error, 'UNKNOWN_ERROR');
    return new CapsaraError(parsed.message, parsed.code, parsed.statusCode, parsed.details, parsed.response, parsed);
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      details: this.details,
      ...(this.retryAfter !== undefined && { retryAfter: this.retryAfter }),
      ...(this.requestId !== undefined && { requestId: this.requestId }),
      ...(this.response && { response: this.response }),
    };
  }
}
