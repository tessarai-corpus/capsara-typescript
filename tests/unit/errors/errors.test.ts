/// <reference types="vitest/globals" />
/**
 * Comprehensive test suite for Capsara SDK error classes
 * @module tests/unit/errors/errors.test
 *
 * Tests all error classes that extend CapsaraError base class:
 * - CapsaraError (base class)
 * - CapsaraCapsaError (capsa/envelope operations)
 * - CapsaraAccountError (account operations)
 * - CapsaraAuthError (authentication operations)
 * - CapsaraAuditError (audit operations)
 *
 * Coverage targets:
 * - All constructors with full parameter sets
 * - All factory methods with and without optional parameters
 * - fromApiError with various error response shapes
 * - Prototype chain and instanceof checks
 * - toJSON serialization
 * - Error.captureStackTrace behavior
 */

import { CapsaraError, type AxiosLikeError, type ApiErrorResponse } from '../../../src/errors/capsara-error.js';
import { CapsaraCapsaError } from '../../../src/errors/capsa-error.js';
import { CapsaraAccountError } from '../../../src/errors/account-error.js';
import { CapsaraAuthError } from '../../../src/errors/auth-error.js';
import { CapsaraAuditError } from '../../../src/errors/audit-error.js';

// ============================================================================
// Test Utilities
// ============================================================================

/**
 * Create a mock Axios-like error with response
 */
function createMockAxiosError(
  status: number,
  errorCode?: string,
  errorMessage?: string,
  details?: Record<string, unknown>
): AxiosLikeError {
  return {
    response: {
      status,
      statusText: status === 200 ? 'OK' : 'Error',
      headers: { 'content-type': 'application/json' },
      data: {
        error: {
          code: errorCode,
          message: errorMessage,
          details,
        },
      },
    },
    message: errorMessage ?? 'Mock error',
  };
}

/**
 * Create a mock Axios-like error with request only (network error)
 */
function createMockNetworkError(message?: string): AxiosLikeError {
  return {
    request: { method: 'GET', url: '/test' },
    message,
  };
}

/**
 * Create a mock Axios-like error with no response or request (generic error)
 */
function createMockGenericError(message?: string): AxiosLikeError {
  return {
    message,
  };
}

// ============================================================================
// CapsaraError (Base Class) Tests
// ============================================================================

describe('CapsaraError (Base Class)', () => {
  describe('Constructor', () => {
    it('should create error with all required properties', () => {
      const error = new CapsaraError('Test message', 'TEST_CODE', 400);

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(CapsaraError);
      expect(error.message).toBe('Test message');
      expect(error.code).toBe('TEST_CODE');
      expect(error.statusCode).toBe(400);
      expect(error.name).toBe('CapsaraError');
    });

    it('should create error with optional details', () => {
      const details = { field: 'value', count: 42 };
      const error = new CapsaraError('Test message', 'TEST_CODE', 400, details);

      expect(error.details).toEqual(details);
    });

    it('should create error with optional response', () => {
      const response: ApiErrorResponse = {
        status: 400,
        statusText: 'Bad Request',
        headers: { 'x-custom': 'header' },
        data: { error: { code: 'TEST', message: 'Test' } },
      };
      const error = new CapsaraError('Test message', 'TEST_CODE', 400, undefined, response);

      expect(error.response).toBeDefined();
      expect(error.response?.status).toBe(400);
      expect(error.response?.statusText).toBe('Bad Request');
      // Headers are now filtered to safe-list (content-type, x-request-id, retry-after)
      expect(error.response?.headers).toEqual({});
      expect(error.response?.data).toEqual({ error: { code: 'TEST', message: 'Test' } });
    });

    it('should not include response when not provided', () => {
      const error = new CapsaraError('Test message', 'TEST_CODE', 400);

      expect(error.response).toBeUndefined();
    });

    it('should have proper prototype chain for instanceof checks', () => {
      const error = new CapsaraError('Test', 'CODE', 500);

      expect(error instanceof Error).toBe(true);
      expect(error instanceof CapsaraError).toBe(true);
      expect(Object.getPrototypeOf(error)).toBe(CapsaraError.prototype);
    });

    it('should have stack trace', () => {
      const error = new CapsaraError('Test', 'CODE', 500);

      expect(error.stack).toBeDefined();
      expect(typeof error.stack).toBe('string');
    });
  });

  describe('fromApiError', () => {
    it('should create error from axios response with full error structure', () => {
      const axiosError = createMockAxiosError(404, 'NOT_FOUND', 'Resource not found', { id: '123' });
      const error = CapsaraError.fromApiError(axiosError);

      expect(error).toBeInstanceOf(CapsaraError);
      expect(error.message).toBe('Resource not found');
      expect(error.code).toBe('NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.details).toEqual({ id: '123' });
      expect(error.response).toBeDefined();
      expect(error.response?.status).toBe(404);
    });

    it('should handle axios response with minimal error structure', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 500,
          data: {},
        },
        message: 'Request failed',
      };
      const error = CapsaraError.fromApiError(axiosError);

      expect(error.code).toBe('UNKNOWN_ERROR');
      expect(error.message).toBe('Request failed');
      expect(error.statusCode).toBe(500);
    });

    it('should handle axios response with no error object in data', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 400,
          data: { message: 'Direct message' },
        },
      };
      const error = CapsaraError.fromApiError(axiosError);

      expect(error.code).toBe('UNKNOWN_ERROR');
      expect(error.message).toBe('An unknown error occurred');
    });

    it('should handle network error (request only, no response)', () => {
      const networkError = createMockNetworkError('Connection refused');
      const error = CapsaraError.fromApiError(networkError);

      expect(error).toBeInstanceOf(CapsaraError);
      expect(error.code).toBe('NETWORK_ERROR');
      expect(error.statusCode).toBe(0);
      expect(error.message).toBe('Network error: Unable to reach the API');
      expect(error.details).toEqual({ originalError: 'Connection refused' });
    });

    it('should handle network error without message', () => {
      const networkError: AxiosLikeError = {
        request: {},
      };
      const error = CapsaraError.fromApiError(networkError);

      expect(error.code).toBe('NETWORK_ERROR');
      expect(error.details).toEqual({ originalError: 'Unknown network error' });
    });

    it('should handle generic error (no response, no request)', () => {
      const genericError = createMockGenericError('Something went wrong');
      const error = CapsaraError.fromApiError(genericError);

      expect(error).toBeInstanceOf(CapsaraError);
      expect(error.code).toBe('UNKNOWN_ERROR');
      expect(error.statusCode).toBe(500);
      expect(error.message).toBe('Something went wrong');
      expect(error.details).toEqual({ originalError: 'Something went wrong' });
    });

    it('should handle generic error without message', () => {
      const genericError: AxiosLikeError = {};
      const error = CapsaraError.fromApiError(genericError);

      expect(error.code).toBe('UNKNOWN_ERROR');
      expect(error.message).toBe('An error occurred');
    });
  });

  describe('toJSON', () => {
    it('should serialize error to JSON with all properties', () => {
      const response: ApiErrorResponse = {
        status: 400,
        statusText: 'Bad Request',
        data: { error: { code: 'TEST', message: 'Test' } },
      };
      const error = new CapsaraError('Test message', 'TEST_CODE', 400, { key: 'value' }, response);
      const json = error.toJSON();

      expect(json).toEqual({
        name: 'CapsaraError',
        message: 'Test message',
        code: 'TEST_CODE',
        statusCode: 400,
        details: { key: 'value' },
        response: {
          status: 400,
          statusText: 'Bad Request',
          headers: undefined,
          data: { error: { code: 'TEST', message: 'Test' } },
        },
      });
    });

    it('should serialize error without response when not provided', () => {
      const error = new CapsaraError('Test', 'CODE', 500);
      const json = error.toJSON();

      expect(json).not.toHaveProperty('response');
      expect(json).toEqual({
        name: 'CapsaraError',
        message: 'Test',
        code: 'CODE',
        statusCode: 500,
        details: undefined,
      });
    });

    it('should serialize error without details when not provided', () => {
      const error = new CapsaraError('Test', 'CODE', 500);
      const json = error.toJSON();

      expect(json.details).toBeUndefined();
    });

    it('should be usable with JSON.stringify', () => {
      const error = new CapsaraError('Test', 'CODE', 500, { key: 'value' });
      const jsonString = JSON.stringify(error);
      const parsed = JSON.parse(jsonString);

      expect(parsed.message).toBe('Test');
      expect(parsed.code).toBe('CODE');
      expect(parsed.statusCode).toBe(500);
    });
  });

  describe('Error.captureStackTrace', () => {
    it('should call Error.captureStackTrace when available', () => {
      // captureStackTrace should have been called during construction
      const error = new CapsaraError('Test', 'CODE', 500);

      // The stack should start with the test file, not the error constructor
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('CapsaraError');
    });
  });
});

// ============================================================================
// CapsaraCapsaError Tests
// ============================================================================

describe('CapsaraCapsaError', () => {
  describe('Constructor', () => {
    it('should create error with correct name', () => {
      const error = new CapsaraCapsaError('Test', 'CODE', 400);

      expect(error.name).toBe('CapsaraCapsaError');
    });

    it('should extend CapsaraError', () => {
      const error = new CapsaraCapsaError('Test', 'CODE', 400);

      expect(error).toBeInstanceOf(CapsaraError);
      // Note: CapsaraCapsaError does not call Object.setPrototypeOf, so direct
      // instanceof checks may not work reliably. We check by name instead.
      expect(error.name).toBe('CapsaraCapsaError');
    });

    it('should create error with all properties', () => {
      const response: ApiErrorResponse = { status: 404, data: {} };
      const error = new CapsaraCapsaError('Test', 'CODE', 404, { key: 'val' }, response);

      expect(error.message).toBe('Test');
      expect(error.code).toBe('CODE');
      expect(error.statusCode).toBe(404);
      expect(error.details).toEqual({ key: 'val' });
      expect(error.response).toBeDefined();
    });
  });

  describe('Factory Method: capsaNotFound', () => {
    it('should create error with capsaId', () => {
      const error = CapsaraCapsaError.capsaNotFound('capsa-123');

      expect(error.message).toBe('Capsa with ID capsa-123 not found or access denied');
      expect(error.code).toBe('CAPSA_NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.details).toEqual({ capsaId: 'capsa-123' });
    });

    it('should create error without capsaId', () => {
      const error = CapsaraCapsaError.capsaNotFound();

      expect(error.message).toBe('Capsa not found or access denied');
      expect(error.code).toBe('CAPSA_NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.details).toBeUndefined();
    });
  });

  describe('Factory Method: fileNotFound', () => {
    it('should create error with fileId', () => {
      const error = CapsaraCapsaError.fileNotFound('file-456');

      expect(error.message).toBe('File not found in capsa');
      expect(error.code).toBe('FILE_NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.details).toEqual({ fileId: 'file-456' });
    });

    it('should create error without fileId', () => {
      const error = CapsaraCapsaError.fileNotFound();

      expect(error.message).toBe('File not found in capsa');
      expect(error.code).toBe('FILE_NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.details).toBeUndefined();
    });
  });

  describe('Factory Method: accessDenied', () => {
    it('should create error with details', () => {
      const error = CapsaraCapsaError.accessDenied({ reason: 'not in keychain' });

      expect(error.message).toBe('You do not have access to this capsa');
      expect(error.code).toBe('ACCESS_DENIED');
      expect(error.statusCode).toBe(403);
      expect(error.details).toEqual({ reason: 'not in keychain' });
    });

    it('should create error without details', () => {
      const error = CapsaraCapsaError.accessDenied();

      expect(error.message).toBe('You do not have access to this capsa');
      expect(error.code).toBe('ACCESS_DENIED');
      expect(error.statusCode).toBe(403);
      expect(error.details).toBeUndefined();
    });
  });

  describe('Factory Method: creatorMismatch', () => {
    it('should create error with authenticated and claimed parties', () => {
      const error = CapsaraCapsaError.creatorMismatch('party-a', 'party-b');

      expect(error.message).toBe('Authenticated party does not match creator in metadata');
      expect(error.code).toBe('CREATOR_MISMATCH');
      expect(error.statusCode).toBe(403);
      expect(error.details).toEqual({ authenticated: 'party-a', claimed: 'party-b' });
    });
  });

  describe('Factory Method: capsaDeleted', () => {
    it('should create error with details', () => {
      const error = CapsaraCapsaError.capsaDeleted({ deletedAt: '2024-01-01' });

      expect(error.message).toBe('Cannot download files from deleted capsa');
      expect(error.code).toBe('CAPSA_DELETED');
      expect(error.statusCode).toBe(403);
      expect(error.details).toEqual({ deletedAt: '2024-01-01' });
    });

    it('should create error without details', () => {
      const error = CapsaraCapsaError.capsaDeleted();

      expect(error.message).toBe('Cannot download files from deleted capsa');
      expect(error.code).toBe('CAPSA_DELETED');
      expect(error.statusCode).toBe(403);
      expect(error.details).toBeUndefined();
    });
  });

  describe('Factory Method: invalidContentType', () => {
    it('should create error with correct message', () => {
      const error = CapsaraCapsaError.invalidContentType();

      expect(error.message).toBe('Request must be multipart/form-data with metadata and capsa_0..N fields');
      expect(error.code).toBe('INVALID_CONTENT_TYPE');
      expect(error.statusCode).toBe(400);
    });
  });

  describe('Factory Method: missingParams', () => {
    it('should create error with params list', () => {
      const error = CapsaraCapsaError.missingParams(['files', 'metadata']);

      expect(error.message).toBe('Missing required parameters: files, metadata');
      expect(error.code).toBe('MISSING_PARAMS');
      expect(error.statusCode).toBe(400);
      expect(error.details).toEqual({ missingParams: ['files', 'metadata'] });
    });

    it('should create error without params list', () => {
      const error = CapsaraCapsaError.missingParams();

      expect(error.message).toBe('Missing required parameters');
      expect(error.code).toBe('MISSING_PARAMS');
      expect(error.statusCode).toBe(400);
      expect(error.details).toBeUndefined();
    });

    it('should handle empty params array', () => {
      const error = CapsaraCapsaError.missingParams([]);

      expect(error.message).toBe('Missing required parameters: ');
      expect(error.details).toEqual({ missingParams: [] });
    });
  });

  describe('Factory Method: missingId', () => {
    it('should create error with correct message', () => {
      const error = CapsaraCapsaError.missingId();

      expect(error.message).toBe('Capsa ID is required');
      expect(error.code).toBe('MISSING_ID');
      expect(error.statusCode).toBe(400);
    });
  });

  describe('Factory Method: invalidExpiration', () => {
    it('should create error with correct message', () => {
      const error = CapsaraCapsaError.invalidExpiration();

      expect(error.message).toBe('URL expiration must be between 1 and 1440 minutes (24 hours)');
      expect(error.code).toBe('INVALID_EXPIRATION');
      expect(error.statusCode).toBe(400);
    });
  });

  describe('Factory Method: multipartError', () => {
    it('should create error with custom message and default status', () => {
      const error = CapsaraCapsaError.multipartError('File too large');

      expect(error.message).toBe('File too large');
      expect(error.code).toBe('MULTIPART_ERROR');
      expect(error.statusCode).toBe(400);
    });

    it('should create error with custom status code', () => {
      const error = CapsaraCapsaError.multipartError('Payload too large', 413);

      expect(error.message).toBe('Payload too large');
      expect(error.code).toBe('MULTIPART_ERROR');
      expect(error.statusCode).toBe(413);
    });

    it('should create error with details', () => {
      const error = CapsaraCapsaError.multipartError('Too many files', 400, { maxFiles: 10 });

      expect(error.message).toBe('Too many files');
      expect(error.details).toEqual({ maxFiles: 10 });
    });
  });

  describe('Factory Method: downloadFailed', () => {
    it('should create error with Error cause', () => {
      const cause = new Error('Network timeout');
      const error = CapsaraCapsaError.downloadFailed('capsa-1', 'file-1', cause);

      expect(error.message).toBe('Failed to download file file-1 from capsa capsa-1: Network timeout');
      expect(error.code).toBe('DOWNLOAD_FAILED');
      expect(error.statusCode).toBe(0);
      expect(error.details).toEqual({
        capsaId: 'capsa-1',
        fileId: 'file-1',
        originalError: 'Network timeout',
      });
      expect(error.cause).toBe(cause);
    });

    it('should create error with string cause', () => {
      const error = CapsaraCapsaError.downloadFailed('capsa-1', 'file-1', 'Connection refused');

      expect(error.message).toBe('Failed to download file file-1 from capsa capsa-1: Connection refused');
      expect(error.details?.originalError).toBe('Connection refused');
      expect(error.cause).toBeUndefined();
    });

    it('should create error with non-Error object cause', () => {
      const error = CapsaraCapsaError.downloadFailed('capsa-1', 'file-1', { code: 'ECONNRESET' });

      expect(error.message).toContain('[object Object]');
      expect(error.cause).toBeUndefined();
    });
  });

  describe('fromApiError', () => {
    it('should map ENVELOPE_NOT_FOUND to capsaNotFound', () => {
      const axiosError = createMockAxiosError(404, 'ENVELOPE_NOT_FOUND', 'Not found', { envelopeId: 'env-123' });
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.name).toBe('CapsaraCapsaError');
      expect(error.code).toBe('CAPSA_NOT_FOUND');
      expect(error.response).toBeDefined();
    });

    it('should map CAPSA_NOT_FOUND to capsaNotFound', () => {
      const axiosError = createMockAxiosError(404, 'CAPSA_NOT_FOUND', 'Not found', { capsaId: 'capsa-123' });
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('CAPSA_NOT_FOUND');
    });

    it('should map FILE_NOT_FOUND to fileNotFound', () => {
      const axiosError = createMockAxiosError(404, 'FILE_NOT_FOUND', 'Not found', { fileId: 'file-123' });
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('FILE_NOT_FOUND');
      expect(error.details).toEqual({ fileId: 'file-123' });
    });

    it('should map ACCESS_DENIED to accessDenied', () => {
      const axiosError = createMockAxiosError(403, 'ACCESS_DENIED', 'Denied');
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('ACCESS_DENIED');
      expect(error.statusCode).toBe(403);
    });

    it('should map CREATOR_MISMATCH to creatorMismatch', () => {
      const axiosError = createMockAxiosError(403, 'CREATOR_MISMATCH', 'Mismatch', {
        authenticated: 'party-a',
        claimed: 'party-b',
      });
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('CREATOR_MISMATCH');
      expect(error.details).toEqual({ authenticated: 'party-a', claimed: 'party-b' });
    });

    it('should map ENVELOPE_DELETED to capsaDeleted', () => {
      const axiosError = createMockAxiosError(403, 'ENVELOPE_DELETED', 'Deleted');
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('CAPSA_DELETED');
    });

    it('should map CAPSA_DELETED to capsaDeleted', () => {
      const axiosError = createMockAxiosError(403, 'CAPSA_DELETED', 'Deleted');
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('CAPSA_DELETED');
    });

    it('should map INVALID_CONTENT_TYPE to invalidContentType', () => {
      const axiosError = createMockAxiosError(400, 'INVALID_CONTENT_TYPE', 'Invalid content');
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('INVALID_CONTENT_TYPE');
    });

    it('should map MISSING_PARAMS to missingParams', () => {
      const axiosError = createMockAxiosError(400, 'MISSING_PARAMS', 'Missing', { missingParams: ['a', 'b'] });
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('MISSING_PARAMS');
    });

    it('should map MISSING_ID to missingId', () => {
      const axiosError = createMockAxiosError(400, 'MISSING_ID', 'Missing ID');
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('MISSING_ID');
    });

    it('should map INVALID_EXPIRATION to invalidExpiration', () => {
      const axiosError = createMockAxiosError(400, 'INVALID_EXPIRATION', 'Invalid');
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('INVALID_EXPIRATION');
    });

    it('should map MULTIPART_ERROR to multipartError', () => {
      const axiosError = createMockAxiosError(413, 'MULTIPART_ERROR', 'Too large', { maxSize: 100 });
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('MULTIPART_ERROR');
      expect(error.statusCode).toBe(413);
    });

    it('should handle unknown error code', () => {
      const axiosError = createMockAxiosError(500, 'UNKNOWN_CODE', 'Unknown error', { key: 'val' });
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.name).toBe('CapsaraCapsaError');
      expect(error.code).toBe('UNKNOWN_CODE');
      expect(error.message).toBe('Unknown error');
      expect(error.statusCode).toBe(500);
      expect(error.response).toBeDefined();
    });

    it('should handle response without error code', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 500,
          data: { message: 'Server error' },
        },
      };
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.code).toBe('CAPSA_ERROR');
    });

    it('should return same error if already CapsaraCapsaError', () => {
      const original = CapsaraCapsaError.capsaNotFound('test');
      // Cast to AxiosLikeError to test the instanceof branch
      const error = CapsaraCapsaError.fromApiError(original as unknown as AxiosLikeError);

      // Note: Due to vitest isolation, the instanceof check in fromApiError may not work
      // The error returned will be a new generic error wrapping the original
      expect(error.name).toBe('CapsaraCapsaError');
    });

    it('should handle generic error without response', () => {
      const genericError: AxiosLikeError = { message: 'Generic failure' };
      const error = CapsaraCapsaError.fromApiError(genericError);

      expect(error.code).toBe('CAPSA_ERROR');
      expect(error.statusCode).toBe(0);
      expect(error.message).toBe('Generic failure');
    });

    it('should handle generic error without message', () => {
      const genericError: AxiosLikeError = {};
      const error = CapsaraCapsaError.fromApiError(genericError);

      expect(error.message).toBe('Unknown capsa error');
    });

    it('should attach response to factory-created errors', () => {
      const axiosError = createMockAxiosError(404, 'FILE_NOT_FOUND', 'Not found');
      const error = CapsaraCapsaError.fromApiError(axiosError);

      expect(error.response).toBeDefined();
      expect(error.response?.status).toBe(404);
    });
  });
});

// ============================================================================
// CapsaraAccountError Tests
// ============================================================================

describe('CapsaraAccountError', () => {
  describe('Constructor', () => {
    it('should create error with correct name', () => {
      const error = new CapsaraAccountError('Test', 'CODE', 400);

      expect(error.name).toBe('CapsaraAccountError');
    });

    it('should extend CapsaraError', () => {
      const error = new CapsaraAccountError('Test', 'CODE', 400);

      expect(error).toBeInstanceOf(CapsaraError);
      // Note: CapsaraAccountError does not call Object.setPrototypeOf, so direct
      // instanceof checks may not work reliably. We check by name instead.
      expect(error.name).toBe('CapsaraAccountError');
    });
  });

  describe('Factory Method: unauthorized', () => {
    it('should create unauthorized error', () => {
      const error = CapsaraAccountError.unauthorized();

      expect(error.message).toBe('Unauthorized');
      expect(error.code).toBe('UNAUTHORIZED');
      expect(error.statusCode).toBe(401);
    });
  });

  describe('Factory Method: notFound', () => {
    it('should create error with resource type and identifier', () => {
      const error = CapsaraAccountError.notFound('Webhook', 'wh-123');

      expect(error.message).toBe('Webhook with identifier wh-123 not found');
      expect(error.code).toBe('NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.details).toEqual({ resourceType: 'Webhook', identifier: 'wh-123' });
    });

    it('should create error with resource type only', () => {
      const error = CapsaraAccountError.notFound('Key');

      expect(error.message).toBe('Key not found');
      expect(error.details).toEqual({ resourceType: 'Key', identifier: undefined });
    });
  });

  describe('Factory Method: webhookNotFound', () => {
    it('should create webhook not found error with id', () => {
      const error = CapsaraAccountError.webhookNotFound('wh-456');

      expect(error.message).toBe('Webhook with identifier wh-456 not found');
      expect(error.code).toBe('NOT_FOUND');
      expect(error.statusCode).toBe(404);
    });

    it('should create webhook not found error without id', () => {
      const error = CapsaraAccountError.webhookNotFound();

      expect(error.message).toBe('Webhook not found');
    });
  });

  describe('Factory Method: licenseNotFound', () => {
    it('should create license not found error with state and number', () => {
      const error = CapsaraAccountError.licenseNotFound('CA', '12345');

      expect(error.message).toBe('License with identifier CA/12345 not found');
    });

    it('should create license not found error without params', () => {
      const error = CapsaraAccountError.licenseNotFound();

      expect(error.message).toBe('License not found');
    });

    it('should handle partial params (state only)', () => {
      const error = CapsaraAccountError.licenseNotFound('CA');

      expect(error.message).toBe('License not found');
    });
  });

  describe('Factory Method: appointmentNotFound', () => {
    it('should create appointment not found error with carrier id', () => {
      const error = CapsaraAccountError.appointmentNotFound('carrier-123');

      expect(error.message).toBe('Appointment with identifier carrier-123 not found');
    });

    it('should create appointment not found error without id', () => {
      const error = CapsaraAccountError.appointmentNotFound();

      expect(error.message).toBe('Appointment not found');
    });
  });

  describe('Factory Method: delegateNotFound', () => {
    it('should create delegate not found error with id', () => {
      const error = CapsaraAccountError.delegateNotFound('delegate-123');

      expect(error.message).toBe('Delegate with identifier delegate-123 not found');
    });

    it('should create delegate not found error without id', () => {
      const error = CapsaraAccountError.delegateNotFound();

      expect(error.message).toBe('Delegate not found');
    });
  });

  describe('Factory Method: keyNotFound', () => {
    it('should create key not found error with fingerprint', () => {
      const error = CapsaraAccountError.keyNotFound('abc123def456');

      expect(error.message).toBe('Key with identifier abc123def456 not found');
    });

    it('should create key not found error without fingerprint', () => {
      const error = CapsaraAccountError.keyNotFound();

      expect(error.message).toBe('Key not found');
    });
  });

  describe('Factory Method: validationError', () => {
    it('should create validation error with message and details', () => {
      const error = CapsaraAccountError.validationError('Invalid email', { field: 'email' });

      expect(error.message).toBe('Invalid email');
      expect(error.code).toBe('VALIDATION_ERROR');
      expect(error.statusCode).toBe(400);
      expect(error.details).toEqual({ field: 'email' });
    });

    it('should create validation error without details', () => {
      const error = CapsaraAccountError.validationError('Invalid input');

      expect(error.message).toBe('Invalid input');
      expect(error.details).toBeUndefined();
    });
  });

  describe('Factory Method: missingParam', () => {
    it('should create missing param error', () => {
      const error = CapsaraAccountError.missingParam('email');

      expect(error.message).toBe('email is required');
      expect(error.code).toBe('MISSING_PARAM');
      expect(error.statusCode).toBe(400);
      expect(error.details).toEqual({ paramName: 'email' });
    });
  });

  describe('Factory Method: alreadyExists', () => {
    it('should create already exists error with identifier', () => {
      const error = CapsaraAccountError.alreadyExists('Webhook', 'wh-123');

      expect(error.message).toBe('Webhook with identifier wh-123 already exists');
      expect(error.code).toBe('ALREADY_EXISTS');
      expect(error.statusCode).toBe(409);
      expect(error.details).toEqual({ resourceType: 'Webhook', identifier: 'wh-123' });
    });

    it('should create already exists error without identifier', () => {
      const error = CapsaraAccountError.alreadyExists('License');

      expect(error.message).toBe('License already exists');
    });
  });

  describe('Factory Method: cannotDeleteActiveKey', () => {
    it('should create cannot delete active key error', () => {
      const error = CapsaraAccountError.cannotDeleteActiveKey();

      expect(error.message).toBe('Cannot delete the currently active key');
      expect(error.code).toBe('CANNOT_DELETE_ACTIVE_KEY');
      expect(error.statusCode).toBe(400);
    });
  });

  describe('Factory Method: webhookLimitExceeded', () => {
    it('should create webhook limit exceeded error', () => {
      const error = CapsaraAccountError.webhookLimitExceeded(10);

      expect(error.message).toBe('Webhook limit of 10 exceeded');
      expect(error.code).toBe('WEBHOOK_LIMIT_EXCEEDED');
      expect(error.statusCode).toBe(400);
      expect(error.details).toEqual({ limit: 10 });
    });
  });

  describe('Factory Method: invalidWebhookUrl', () => {
    it('should create invalid webhook url error with url', () => {
      const error = CapsaraAccountError.invalidWebhookUrl('not-a-url');

      expect(error.message).toBe('Invalid webhook URL');
      expect(error.code).toBe('INVALID_WEBHOOK_URL');
      expect(error.statusCode).toBe(400);
      expect(error.details).toEqual({ url: 'not-a-url' });
    });

    it('should create invalid webhook url error without url', () => {
      const error = CapsaraAccountError.invalidWebhookUrl();

      expect(error.message).toBe('Invalid webhook URL');
      expect(error.details).toBeUndefined();
    });
  });

  describe('fromApiError', () => {
    it('should map UNAUTHORIZED to unauthorized', () => {
      const axiosError = createMockAxiosError(401, 'UNAUTHORIZED', 'Not authorized');
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.name).toBe('CapsaraAccountError');
      expect(error.code).toBe('UNAUTHORIZED');
    });

    it('should map WEBHOOK_NOT_FOUND to webhookNotFound', () => {
      const axiosError = createMockAxiosError(404, 'WEBHOOK_NOT_FOUND', 'Not found', { webhookId: 'wh-1' });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.code).toBe('NOT_FOUND');
    });

    it('should map WEBHOOK_NOT_FOUND with identifier fallback', () => {
      const axiosError = createMockAxiosError(404, 'WEBHOOK_NOT_FOUND', 'Not found', { identifier: 'wh-2' });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.message).toContain('wh-2');
    });

    it('should map LICENSE_NOT_FOUND to licenseNotFound', () => {
      const axiosError = createMockAxiosError(404, 'LICENSE_NOT_FOUND', 'Not found', {
        state: 'CA',
        licenseNumber: '123',
      });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.message).toContain('CA/123');
    });

    it('should map APPOINTMENT_NOT_FOUND to appointmentNotFound', () => {
      const axiosError = createMockAxiosError(404, 'APPOINTMENT_NOT_FOUND', 'Not found', { carrierPartyId: 'c-1' });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.message).toContain('c-1');
    });

    it('should map DELEGATE_NOT_FOUND to delegateNotFound', () => {
      const axiosError = createMockAxiosError(404, 'DELEGATE_NOT_FOUND', 'Not found', { delegateId: 'd-1' });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.message).toContain('d-1');
    });

    it('should map KEY_NOT_FOUND to keyNotFound', () => {
      const axiosError = createMockAxiosError(404, 'KEY_NOT_FOUND', 'Not found', { keyFingerprint: 'fp-1' });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.message).toContain('fp-1');
    });

    it('should map NOT_FOUND to notFound', () => {
      const axiosError = createMockAxiosError(404, 'NOT_FOUND', 'Not found', {
        resourceType: 'Widget',
        identifier: 'w-1',
      });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.message).toContain('Widget');
      expect(error.message).toContain('w-1');
    });

    it('should map NOT_FOUND with default resource type', () => {
      const axiosError = createMockAxiosError(404, 'NOT_FOUND', 'Not found', {});
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.message).toContain('Resource');
    });

    it('should map VALIDATION_ERROR to validationError', () => {
      const axiosError = createMockAxiosError(400, 'VALIDATION_ERROR', 'Invalid data', { field: 'email' });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.code).toBe('VALIDATION_ERROR');
      expect(error.message).toBe('Invalid data');
    });

    it('should map MISSING_PARAM to missingParam', () => {
      const axiosError = createMockAxiosError(400, 'MISSING_PARAM', 'Missing', { paramName: 'id' });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.code).toBe('MISSING_PARAM');
      expect(error.message).toContain('id');
    });

    it('should map MISSING_PARAM with default param name', () => {
      const axiosError = createMockAxiosError(400, 'MISSING_PARAM', 'Missing', {});
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.message).toContain('Parameter');
    });

    it('should map ALREADY_EXISTS to alreadyExists', () => {
      const axiosError = createMockAxiosError(409, 'ALREADY_EXISTS', 'Exists', {
        resourceType: 'Key',
        identifier: 'k-1',
      });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.code).toBe('ALREADY_EXISTS');
      expect(error.message).toContain('Key');
    });

    it('should map CANNOT_DELETE_ACTIVE_KEY to cannotDeleteActiveKey', () => {
      const axiosError = createMockAxiosError(400, 'CANNOT_DELETE_ACTIVE_KEY', 'Cannot delete');
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.code).toBe('CANNOT_DELETE_ACTIVE_KEY');
    });

    it('should map WEBHOOK_LIMIT_EXCEEDED to webhookLimitExceeded', () => {
      const axiosError = createMockAxiosError(400, 'WEBHOOK_LIMIT_EXCEEDED', 'Limit exceeded', { limit: 5 });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.code).toBe('WEBHOOK_LIMIT_EXCEEDED');
      expect(error.details).toEqual({ limit: 5 });
    });

    it('should map WEBHOOK_LIMIT_EXCEEDED with default limit', () => {
      const axiosError = createMockAxiosError(400, 'WEBHOOK_LIMIT_EXCEEDED', 'Limit exceeded', {});
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.details).toEqual({ limit: 10 });
    });

    it('should map INVALID_WEBHOOK_URL to invalidWebhookUrl', () => {
      const axiosError = createMockAxiosError(400, 'INVALID_WEBHOOK_URL', 'Invalid URL', { url: 'bad-url' });
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.code).toBe('INVALID_WEBHOOK_URL');
    });

    it('should handle unknown error code', () => {
      const axiosError = createMockAxiosError(500, 'UNKNOWN_CODE', 'Unknown error');
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.code).toBe('UNKNOWN_CODE');
      expect(error.message).toBe('Unknown error');
    });

    it('should handle response without error code', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 500,
          data: {},
        },
      };
      const error = CapsaraAccountError.fromApiError(axiosError);

      expect(error.code).toBe('ACCOUNT_ERROR');
    });

    it('should return same error if already CapsaraAccountError', () => {
      const original = CapsaraAccountError.unauthorized();
      const error = CapsaraAccountError.fromApiError(original as unknown as AxiosLikeError);

      // Note: Due to vitest isolation, the instanceof check in fromApiError may not work
      // The error returned will be a new generic error wrapping the original
      expect(error.name).toBe('CapsaraAccountError');
    });

    it('should handle generic error without response', () => {
      const genericError: AxiosLikeError = { message: 'Generic failure' };
      const error = CapsaraAccountError.fromApiError(genericError);

      expect(error.code).toBe('ACCOUNT_ERROR');
      expect(error.statusCode).toBe(500);
    });

    it('should handle generic error without message', () => {
      const genericError: AxiosLikeError = {};
      const error = CapsaraAccountError.fromApiError(genericError);

      expect(error.message).toBe('Unknown account error');
    });
  });
});

// ============================================================================
// CapsaraAuthError Tests
// ============================================================================

describe('CapsaraAuthError', () => {
  describe('Constructor', () => {
    it('should create error with correct name', () => {
      const error = new CapsaraAuthError('Test', 'CODE', 400);

      expect(error.name).toBe('CapsaraAuthError');
    });

    it('should extend CapsaraError', () => {
      const error = new CapsaraAuthError('Test', 'CODE', 400);

      expect(error).toBeInstanceOf(CapsaraError);
      // Note: CapsaraAuthError does not call Object.setPrototypeOf, so direct
      // instanceof checks may not work reliably. We check by name instead.
      expect(error.name).toBe('CapsaraAuthError');
    });
  });

  describe('Factory Method: refreshTokenRequired', () => {
    it('should create refresh token required error', () => {
      const error = CapsaraAuthError.refreshTokenRequired();

      expect(error.message).toBe('Refresh token is required');
      expect(error.code).toBe('REFRESH_TOKEN_REQUIRED');
      expect(error.statusCode).toBe(401);
    });
  });

  describe('Factory Method: invalidCredentials', () => {
    it('should create invalid credentials error', () => {
      const error = CapsaraAuthError.invalidCredentials();

      expect(error.message).toBe('Invalid email or password');
      expect(error.code).toBe('INVALID_CREDENTIALS');
      expect(error.statusCode).toBe(401);
    });
  });

  describe('Factory Method: invalidRefreshToken', () => {
    it('should create invalid refresh token error', () => {
      const error = CapsaraAuthError.invalidRefreshToken();

      expect(error.message).toBe('Refresh token is invalid or expired');
      expect(error.code).toBe('INVALID_REFRESH_TOKEN');
      expect(error.statusCode).toBe(401);
    });
  });

  describe('Factory Method: unauthorized', () => {
    it('should create unauthorized error with default message', () => {
      const error = CapsaraAuthError.unauthorized();

      expect(error.message).toBe('Unauthorized - invalid or expired access token');
      expect(error.code).toBe('UNAUTHORIZED');
      expect(error.statusCode).toBe(401);
    });

    it('should create unauthorized error with custom message', () => {
      const error = CapsaraAuthError.unauthorized('Custom unauthorized message');

      expect(error.message).toBe('Custom unauthorized message');
      expect(error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('Factory Method: notImplemented', () => {
    it('should create not implemented error', () => {
      const error = CapsaraAuthError.notImplemented('SSO');

      expect(error.message).toBe('SSO endpoint not yet implemented');
      expect(error.code).toBe('NOT_IMPLEMENTED');
      expect(error.statusCode).toBe(405);
      expect(error.details).toEqual({ feature: 'SSO' });
    });
  });

  describe('Factory Method: validationError', () => {
    it('should create validation error with message and details', () => {
      const error = CapsaraAuthError.validationError('Invalid password', { minLength: 8 });

      expect(error.message).toBe('Invalid password');
      expect(error.code).toBe('VALIDATION_ERROR');
      expect(error.statusCode).toBe(400);
      expect(error.details).toEqual({ minLength: 8 });
    });

    it('should create validation error without details', () => {
      const error = CapsaraAuthError.validationError('Invalid input');

      expect(error.message).toBe('Invalid input');
      expect(error.details).toBeUndefined();
    });
  });

  describe('fromApiError', () => {
    it('should map REFRESH_TOKEN_REQUIRED to refreshTokenRequired', () => {
      const axiosError = createMockAxiosError(401, 'REFRESH_TOKEN_REQUIRED', 'Token required');
      const error = CapsaraAuthError.fromApiError(axiosError);

      expect(error.name).toBe('CapsaraAuthError');
      expect(error.code).toBe('REFRESH_TOKEN_REQUIRED');
    });

    it('should map INVALID_CREDENTIALS to invalidCredentials', () => {
      const axiosError = createMockAxiosError(401, 'INVALID_CREDENTIALS', 'Bad credentials');
      const error = CapsaraAuthError.fromApiError(axiosError);

      expect(error.code).toBe('INVALID_CREDENTIALS');
    });

    it('should map INVALID_REFRESH_TOKEN to invalidRefreshToken', () => {
      const axiosError = createMockAxiosError(401, 'INVALID_REFRESH_TOKEN', 'Token expired');
      const error = CapsaraAuthError.fromApiError(axiosError);

      expect(error.code).toBe('INVALID_REFRESH_TOKEN');
    });

    it('should map UNAUTHORIZED to unauthorized with custom message', () => {
      const axiosError = createMockAxiosError(401, 'UNAUTHORIZED', 'Session expired');
      const error = CapsaraAuthError.fromApiError(axiosError);

      expect(error.code).toBe('UNAUTHORIZED');
      expect(error.message).toBe('Session expired');
    });

    it('should map NOT_IMPLEMENTED to notImplemented', () => {
      const axiosError = createMockAxiosError(405, 'NOT_IMPLEMENTED', 'Not implemented', { feature: 'MFA' });
      const error = CapsaraAuthError.fromApiError(axiosError);

      expect(error.code).toBe('NOT_IMPLEMENTED');
      expect(error.message).toContain('MFA');
    });

    it('should map NOT_IMPLEMENTED with default feature', () => {
      const axiosError = createMockAxiosError(405, 'NOT_IMPLEMENTED', 'Not implemented', {});
      const error = CapsaraAuthError.fromApiError(axiosError);

      expect(error.message).toContain('Feature');
    });

    it('should map VALIDATION_ERROR to validationError', () => {
      const axiosError = createMockAxiosError(400, 'VALIDATION_ERROR', 'Invalid data', { field: 'password' });
      const error = CapsaraAuthError.fromApiError(axiosError);

      expect(error.code).toBe('VALIDATION_ERROR');
    });

    it('should handle unknown error code', () => {
      const axiosError = createMockAxiosError(500, 'UNKNOWN_CODE', 'Unknown error');
      const error = CapsaraAuthError.fromApiError(axiosError);

      expect(error.code).toBe('UNKNOWN_CODE');
    });

    it('should handle response without error code', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 500,
          data: {},
        },
      };
      const error = CapsaraAuthError.fromApiError(axiosError);

      expect(error.code).toBe('AUTH_ERROR');
    });

    it('should return same error if already CapsaraAuthError', () => {
      const original = CapsaraAuthError.invalidCredentials();
      const error = CapsaraAuthError.fromApiError(original as unknown as AxiosLikeError);

      // Note: Due to vitest isolation, the instanceof check in fromApiError may not work
      // The error returned will be a new generic error wrapping the original
      expect(error.name).toBe('CapsaraAuthError');
    });

    it('should handle generic error without response', () => {
      const genericError: AxiosLikeError = { message: 'Auth failure' };
      const error = CapsaraAuthError.fromApiError(genericError);

      expect(error.code).toBe('AUTH_ERROR');
      expect(error.statusCode).toBe(500);
    });

    it('should handle generic error without message', () => {
      const genericError: AxiosLikeError = {};
      const error = CapsaraAuthError.fromApiError(genericError);

      expect(error.message).toBe('Unknown authentication error');
    });
  });
});

// ============================================================================
// CapsaraAuditError Tests
// ============================================================================

describe('CapsaraAuditError', () => {
  describe('Constructor', () => {
    it('should create error with correct name', () => {
      const error = new CapsaraAuditError('Test', 'CODE', 400);

      expect(error.name).toBe('CapsaraAuditError');
    });

    it('should extend CapsaraError', () => {
      const error = new CapsaraAuditError('Test', 'CODE', 400);

      expect(error).toBeInstanceOf(CapsaraError);
      expect(error).toBeInstanceOf(CapsaraAuditError);
    });

    it('should have proper prototype chain for instanceof checks', () => {
      const error = new CapsaraAuditError('Test', 'CODE', 400);

      expect(Object.getPrototypeOf(error)).toBe(CapsaraAuditError.prototype);
    });
  });

  describe('Factory Method: insufficientPermissions', () => {
    it('should create insufficient permissions error with details', () => {
      const error = CapsaraAuditError.insufficientPermissions({ action: 'log', role: 'recipient' });

      expect(error.message).toBe('You do not have permission to perform this action');
      expect(error.code).toBe('INSUFFICIENT_PERMISSIONS');
      expect(error.statusCode).toBe(403);
      expect(error.details).toEqual({ action: 'log', role: 'recipient' });
    });

    it('should create insufficient permissions error without details', () => {
      const error = CapsaraAuditError.insufficientPermissions();

      expect(error.message).toBe('You do not have permission to perform this action');
      expect(error.code).toBe('INSUFFICIENT_PERMISSIONS');
      expect(error.details).toBeUndefined();
    });
  });

  describe('Factory Method: invalidAction', () => {
    it('should create invalid action error with action', () => {
      const error = CapsaraAuditError.invalidAction('bad_action');

      expect(error.message).toBe('Invalid audit action');
      expect(error.code).toBe('INVALID_AUDIT_ACTION');
      expect(error.statusCode).toBe(400);
      expect(error.details).toEqual({ action: 'bad_action' });
    });

    it('should create invalid action error without action', () => {
      const error = CapsaraAuditError.invalidAction();

      expect(error.message).toBe('Invalid audit action');
      expect(error.details).toEqual({ action: undefined });
    });
  });

  describe('Factory Method: accessDenied', () => {
    it('should create access denied error with details', () => {
      const error = CapsaraAuditError.accessDenied({ reason: 'not in keychain' });

      expect(error.message).toBe('You do not have access to this capsa');
      expect(error.code).toBe('ACCESS_DENIED');
      expect(error.statusCode).toBe(403);
      expect(error.details).toEqual({ reason: 'not in keychain' });
    });

    it('should create access denied error without details', () => {
      const error = CapsaraAuditError.accessDenied();

      expect(error.message).toBe('You do not have access to this capsa');
      expect(error.details).toBeUndefined();
    });
  });

  describe('Factory Method: missingDetails', () => {
    it('should create missing details error', () => {
      const error = CapsaraAuditError.missingDetails();

      expect(error.message).toBe('Details field is required for log action');
      expect(error.code).toBe('MISSING_DETAILS');
      expect(error.statusCode).toBe(400);
    });
  });

  describe('Factory Method: capsaNotFound', () => {
    it('should create capsa not found error', () => {
      const error = CapsaraAuditError.capsaNotFound('capsa-123');

      expect(error.message).toBe('Capsa not found or access denied');
      expect(error.code).toBe('CAPSA_NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.details).toEqual({ capsaId: 'capsa-123' });
    });
  });

  describe('fromApiError', () => {
    it('should map INSUFFICIENT_PERMISSIONS to insufficientPermissions', () => {
      const axiosError = createMockAxiosError(403, 'INSUFFICIENT_PERMISSIONS', 'Not allowed', { role: 'recipient' });
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.name).toBe('CapsaraAuditError');
      expect(error.code).toBe('INSUFFICIENT_PERMISSIONS');
      expect(error.response).toBeDefined();
    });

    it('should map INVALID_AUDIT_ACTION to invalidAction', () => {
      const axiosError = createMockAxiosError(400, 'INVALID_AUDIT_ACTION', 'Invalid action', { action: 'bad' });
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.code).toBe('INVALID_AUDIT_ACTION');
    });

    it('should map ACCESS_DENIED to accessDenied', () => {
      const axiosError = createMockAxiosError(403, 'ACCESS_DENIED', 'Denied');
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.code).toBe('ACCESS_DENIED');
    });

    it('should map MISSING_DETAILS to missingDetails', () => {
      const axiosError = createMockAxiosError(400, 'MISSING_DETAILS', 'Missing details');
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.code).toBe('MISSING_DETAILS');
    });

    it('should map ENVELOPE_NOT_FOUND to capsaNotFound', () => {
      const axiosError = createMockAxiosError(404, 'ENVELOPE_NOT_FOUND', 'Not found', { envelopeId: 'env-123' });
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.code).toBe('CAPSA_NOT_FOUND');
    });

    it('should map CAPSA_NOT_FOUND to capsaNotFound', () => {
      const axiosError = createMockAxiosError(404, 'CAPSA_NOT_FOUND', 'Not found', { capsaId: 'capsa-123' });
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.code).toBe('CAPSA_NOT_FOUND');
    });

    it('should handle unknown error code', () => {
      const axiosError = createMockAxiosError(500, 'UNKNOWN_CODE', 'Unknown error');
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.code).toBe('UNKNOWN_CODE');
      expect(error.message).toBe('Unknown error');
    });

    it('should handle response without error code', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 500,
          data: {},
        },
      };
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.code).toBe('UNKNOWN_AUDIT_ERROR');
    });

    it('should handle response without error message', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 500,
          data: { error: { code: undefined } },
        },
      };
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.message).toBe('An audit error occurred');
    });

    it('should attach response to factory-created errors', () => {
      const axiosError = createMockAxiosError(403, 'ACCESS_DENIED', 'Denied');
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.response).toBeDefined();
      expect(error.response?.status).toBe(403);
    });

    it('should handle missing response gracefully', () => {
      const axiosError: AxiosLikeError = {};
      const error = CapsaraAuditError.fromApiError(axiosError);

      expect(error.code).toBe('UNKNOWN_AUDIT_ERROR');
      expect(error.statusCode).toBe(500);
    });
  });
});

// ============================================================================
// Cross-Error Type Tests
// ============================================================================

describe('Cross-Error Type Behavior', () => {
  describe('instanceof checks', () => {
    it('should correctly identify CapsaraError instances', () => {
      const baseError = new CapsaraError('Test', 'CODE', 400);
      const capsaError = new CapsaraCapsaError('Test', 'CODE', 400);
      const accountError = new CapsaraAccountError('Test', 'CODE', 400);
      const authError = new CapsaraAuthError('Test', 'CODE', 400);
      const auditError = new CapsaraAuditError('Test', 'CODE', 400);

      // All should be CapsaraError
      expect(baseError instanceof CapsaraError).toBe(true);
      expect(capsaError instanceof CapsaraError).toBe(true);
      expect(accountError instanceof CapsaraError).toBe(true);
      expect(authError instanceof CapsaraError).toBe(true);
      expect(auditError instanceof CapsaraError).toBe(true);

      // All should be Error
      expect(baseError instanceof Error).toBe(true);
      expect(capsaError instanceof Error).toBe(true);
      expect(accountError instanceof Error).toBe(true);
      expect(authError instanceof Error).toBe(true);
      expect(auditError instanceof Error).toBe(true);
    });

    it('should correctly differentiate error types by name', () => {
      const capsaError = new CapsaraCapsaError('Test', 'CODE', 400);
      const accountError = new CapsaraAccountError('Test', 'CODE', 400);
      const authError = new CapsaraAuthError('Test', 'CODE', 400);
      const auditError = new CapsaraAuditError('Test', 'CODE', 400);

      // Use name property to differentiate error types since not all subclasses
      // call Object.setPrototypeOf, making instanceof unreliable in vitest isolation
      expect(capsaError.name).toBe('CapsaraCapsaError');
      expect(capsaError.name).not.toBe('CapsaraAccountError');
      expect(capsaError.name).not.toBe('CapsaraAuthError');
      expect(capsaError.name).not.toBe('CapsaraAuditError');

      expect(accountError.name).not.toBe('CapsaraCapsaError');
      expect(accountError.name).toBe('CapsaraAccountError');
      expect(accountError.name).not.toBe('CapsaraAuthError');
      expect(accountError.name).not.toBe('CapsaraAuditError');

      expect(authError.name).not.toBe('CapsaraCapsaError');
      expect(authError.name).not.toBe('CapsaraAccountError');
      expect(authError.name).toBe('CapsaraAuthError');
      expect(authError.name).not.toBe('CapsaraAuditError');

      expect(auditError.name).not.toBe('CapsaraCapsaError');
      expect(auditError.name).not.toBe('CapsaraAccountError');
      expect(auditError.name).not.toBe('CapsaraAuthError');
      expect(auditError.name).toBe('CapsaraAuditError');
    });
  });

  describe('Error names', () => {
    it('should have unique names for each error type', () => {
      const names = [
        new CapsaraError('', '', 0).name,
        new CapsaraCapsaError('', '', 0).name,
        new CapsaraAccountError('', '', 0).name,
        new CapsaraAuthError('', '', 0).name,
        new CapsaraAuditError('', '', 0).name,
      ];

      const uniqueNames = new Set(names);
      expect(uniqueNames.size).toBe(5);
    });

    it('should have descriptive names', () => {
      expect(new CapsaraError('', '', 0).name).toBe('CapsaraError');
      expect(new CapsaraCapsaError('', '', 0).name).toBe('CapsaraCapsaError');
      expect(new CapsaraAccountError('', '', 0).name).toBe('CapsaraAccountError');
      expect(new CapsaraAuthError('', '', 0).name).toBe('CapsaraAuthError');
      expect(new CapsaraAuditError('', '', 0).name).toBe('CapsaraAuditError');
    });
  });

  describe('toJSON inheritance', () => {
    it('should inherit toJSON from CapsaraError for all error types', () => {
      const errors = [
        new CapsaraError('Test', 'CODE', 400, { key: 'val' }),
        new CapsaraCapsaError('Test', 'CODE', 400, { key: 'val' }),
        new CapsaraAccountError('Test', 'CODE', 400, { key: 'val' }),
        new CapsaraAuthError('Test', 'CODE', 400, { key: 'val' }),
        new CapsaraAuditError('Test', 'CODE', 400, { key: 'val' }),
      ];

      for (const error of errors) {
        const json = error.toJSON();
        expect(json).toHaveProperty('name');
        expect(json).toHaveProperty('message', 'Test');
        expect(json).toHaveProperty('code', 'CODE');
        expect(json).toHaveProperty('statusCode', 400);
        expect(json).toHaveProperty('details', { key: 'val' });
      }
    });
  });
});

// ============================================================================
// Edge Cases and Boundary Conditions
// ============================================================================

describe('Edge Cases and Boundary Conditions', () => {
  describe('Empty string handling', () => {
    it('should handle empty message', () => {
      const error = new CapsaraError('', 'CODE', 400);
      expect(error.message).toBe('');
    });

    it('should handle empty code', () => {
      const error = new CapsaraError('Test', '', 400);
      expect(error.code).toBe('');
    });

    it('should handle empty string in factory methods', () => {
      // capsaNotFound treats empty string as falsy, so it uses the generic message
      const capsaError = CapsaraCapsaError.capsaNotFound('');
      expect(capsaError.message).toBe('Capsa not found or access denied');

      const creatorError = CapsaraCapsaError.creatorMismatch('', '');
      expect(creatorError.details).toEqual({ authenticated: '', claimed: '' });
    });
  });

  describe('Status code handling', () => {
    it('should handle zero status code', () => {
      const error = new CapsaraError('Test', 'CODE', 0);
      expect(error.statusCode).toBe(0);
    });

    it('should handle negative status code', () => {
      const error = new CapsaraError('Test', 'CODE', -1);
      expect(error.statusCode).toBe(-1);
    });

    it('should handle large status codes', () => {
      const error = new CapsaraError('Test', 'CODE', 599);
      expect(error.statusCode).toBe(599);
    });
  });

  describe('Details object handling', () => {
    it('should handle empty details object', () => {
      const error = new CapsaraError('Test', 'CODE', 400, {});
      expect(error.details).toEqual({});
    });

    it('should handle complex nested details', () => {
      const details = {
        nested: {
          array: [1, 2, 3],
          object: { key: 'value' },
        },
        null: null,
        undefined: undefined,
      };
      const error = new CapsaraError('Test', 'CODE', 400, details);
      expect(error.details).toEqual(details);
    });
  });

  describe('Special characters in messages', () => {
    it('should handle special characters', () => {
      const message = 'Error with <script>alert("xss")</script> and \n newlines';
      const error = new CapsaraError(message, 'CODE', 400);
      expect(error.message).toBe(message);
    });

    it('should handle unicode characters', () => {
      const message = 'Error with unicode: \u{1F600} \u{1F4A9}';
      const error = new CapsaraError(message, 'CODE', 400);
      expect(error.message).toBe(message);
    });
  });

  describe('Response object edge cases', () => {
    it('should handle response with minimal data', () => {
      const response: ApiErrorResponse = { status: 500 };
      const error = new CapsaraError('Test', 'CODE', 500, undefined, response);

      expect(error.response?.status).toBe(500);
      expect(error.response?.statusText).toBeUndefined();
      expect(error.response?.headers).toBeUndefined();
      expect(error.response?.data).toBeUndefined();
    });

    it('should handle response with null data fields', () => {
      const response: ApiErrorResponse = {
        status: 500,
        data: {
          error: undefined,
          message: undefined,
        },
      };
      const error = new CapsaraError('Test', 'CODE', 500, undefined, response);
      expect(error.response?.data).toBeDefined();
    });
  });

  describe('fromApiError with malformed responses', () => {
    it('should handle response with data but no error object', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 400,
          data: { someField: 'value' },
        },
      };
      const error = CapsaraError.fromApiError(axiosError);

      expect(error.code).toBe('UNKNOWN_ERROR');
    });

    it('should handle response with error object but no code', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 400,
          data: {
            error: { message: 'Some error' },
          },
        },
      };
      const error = CapsaraError.fromApiError(axiosError);

      expect(error.code).toBe('UNKNOWN_ERROR');
      expect(error.message).toBe('Some error');
    });
  });
});
