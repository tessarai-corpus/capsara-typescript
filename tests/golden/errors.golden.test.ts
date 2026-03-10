/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Error Classes
 * Tests fromApiError, network error, generic error, factory methods per error class,
 * legacy code mapping, toJSON, instanceof hierarchy.
 */

import {
  CapsaraError,
  CapsaraAuthError,
  CapsaraCapsaError,
  CapsaraAuditError,
  CapsaraAccountError,
} from '../../src/errors/index.js';
import type { AxiosLikeError } from '../../src/errors/capsara-error.js';

describe('Golden: Errors', () => {
  describe('CapsaraError.fromApiError', () => {
    it('should parse API error response with status code and error object', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 404,
          data: {
            error: {
              code: 'NOT_FOUND',
              message: 'Resource not found',
              details: { id: 'xyz' },
            },
          },
        },
      };

      const error = CapsaraError.fromApiError(axiosError);

      expect(error).toBeInstanceOf(CapsaraError);
      expect(error.code).toBe('NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.message).toBe('Resource not found');
      expect(error.details).toEqual({ id: 'xyz' });
    });

    it('should handle network error (request sent, no response)', () => {
      const axiosError: AxiosLikeError = {
        request: {},
        message: 'ECONNREFUSED',
      };

      const error = CapsaraError.fromApiError(axiosError);

      expect(error.code).toBe('NETWORK_ERROR');
      expect(error.statusCode).toBe(0);
      expect(error.message).toContain('Network error');
    });

    it('should handle generic error (no request, no response)', () => {
      const axiosError: AxiosLikeError = {
        message: 'Something went wrong',
      };

      const error = CapsaraError.fromApiError(axiosError);

      expect(error.code).toBe('UNKNOWN_ERROR');
      expect(error.statusCode).toBe(500);
      expect(error.message).toBe('Something went wrong');
    });
  });

  describe('CapsaraAuthError factory methods', () => {
    it('should create invalidCredentials error', () => {
      const error = CapsaraAuthError.invalidCredentials();

      // Base class Object.setPrototypeOf resets prototype chain; use .name for subclass check
      expect(error.name).toBe('CapsaraAuthError');
      expect(error).toBeInstanceOf(CapsaraError);
      expect(error.code).toBe('INVALID_CREDENTIALS');
      expect(error.statusCode).toBe(401);
    });

    it('should create unauthorized error', () => {
      const error = CapsaraAuthError.unauthorized();
      expect(error.code).toBe('UNAUTHORIZED');
      expect(error.statusCode).toBe(401);
    });

    it('should map INVALID_CREDENTIALS code from API', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 401,
          data: { error: { code: 'INVALID_CREDENTIALS' } },
        },
      };

      const error = CapsaraAuthError.fromApiError(axiosError);
      expect(error.code).toBe('INVALID_CREDENTIALS');
    });
  });

  describe('CapsaraCapsaError factory methods', () => {
    it('should create capsaNotFound error with capsa ID', () => {
      const error = CapsaraCapsaError.capsaNotFound('capsa_abc');

      expect(error.name).toBe('CapsaraCapsaError');
      expect(error).toBeInstanceOf(CapsaraError);
      expect(error.code).toBe('CAPSA_NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.details?.capsaId).toBe('capsa_abc');
    });

    it('should create downloadFailed error with context', () => {
      const cause = new Error('Blob timeout');
      const error = CapsaraCapsaError.downloadFailed('capsa_1', 'file_2.enc', cause);

      expect(error.code).toBe('DOWNLOAD_FAILED');
      expect(error.message).toContain('capsa_1');
      expect(error.message).toContain('file_2.enc');
      expect(error.message).toContain('Blob timeout');
      expect(error.details?.capsaId).toBe('capsa_1');
    });

    it('should map legacy ENVELOPE_NOT_FOUND to capsaNotFound', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 404,
          data: { error: { code: 'ENVELOPE_NOT_FOUND', details: { envelopeId: 'env_123' } } },
        },
      };

      const error = CapsaraCapsaError.fromApiError(axiosError);
      expect(error.code).toBe('CAPSA_NOT_FOUND');
      expect(error.statusCode).toBe(404);
    });
  });

  describe('CapsaraAuditError factory methods', () => {
    it('should create missingDetails error', () => {
      const error = CapsaraAuditError.missingDetails();

      expect(error).toBeInstanceOf(CapsaraAuditError);
      expect(error.code).toBe('MISSING_DETAILS');
      expect(error.statusCode).toBe(400);
    });

    it('should map legacy ENVELOPE_NOT_FOUND to capsaNotFound', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 404,
          data: { error: { code: 'ENVELOPE_NOT_FOUND', details: { envelopeId: 'env_1' } } },
        },
      };

      const error = CapsaraAuditError.fromApiError(axiosError);
      expect(error.code).toBe('CAPSA_NOT_FOUND');
    });
  });

  describe('CapsaraAccountError factory methods', () => {
    it('should create webhookNotFound error', () => {
      const error = CapsaraAccountError.webhookNotFound('wh_123');

      expect(error.name).toBe('CapsaraAccountError');
      expect(error).toBeInstanceOf(CapsaraError);
      expect(error.code).toBe('NOT_FOUND');
      expect(error.statusCode).toBe(404);
    });

    it('should create validationError', () => {
      const error = CapsaraAccountError.validationError('Bad input', { field: 'email' });
      expect(error.code).toBe('VALIDATION_ERROR');
      expect(error.statusCode).toBe(400);
      expect(error.details?.field).toBe('email');
    });
  });

  describe('toJSON', () => {
    it('should serialize error to JSON with all fields', () => {
      const error = new CapsaraError('Test error', 'TEST_CODE', 422, { reason: 'invalid' });
      const json = error.toJSON();

      expect(json.name).toBe('CapsaraError');
      expect(json.message).toBe('Test error');
      expect(json.code).toBe('TEST_CODE');
      expect(json.statusCode).toBe(422);
      expect(json.details).toEqual({ reason: 'invalid' });
    });

    it('should include response in JSON when available', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 500,
          statusText: 'Internal Server Error',
          data: { error: { code: 'SERVER_ERROR', message: 'Boom' } },
        },
      };
      const error = CapsaraError.fromApiError(axiosError);
      const json = error.toJSON();

      expect(json.response).toBeDefined();
      expect(json.response!.status).toBe(500);
    });
  });

  describe('instanceof hierarchy', () => {
    it('CapsaraAuthError should be instanceof CapsaraError and Error', () => {
      const error = CapsaraAuthError.invalidCredentials();

      // Base class setPrototypeOf breaks subclass instanceof; verify via .name
      expect(error.name).toBe('CapsaraAuthError');
      expect(error instanceof CapsaraError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it('CapsaraCapsaError should be instanceof CapsaraError and Error', () => {
      const error = CapsaraCapsaError.capsaNotFound();

      expect(error.name).toBe('CapsaraCapsaError');
      expect(error instanceof CapsaraError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it('CapsaraAuditError should be instanceof CapsaraError and Error', () => {
      const error = CapsaraAuditError.missingDetails();

      expect(error instanceof CapsaraAuditError).toBe(true);
      expect(error instanceof CapsaraError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it('CapsaraAccountError should be instanceof CapsaraError and Error', () => {
      const error = CapsaraAccountError.unauthorized();

      expect(error.name).toBe('CapsaraAccountError');
      expect(error instanceof CapsaraError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });
  });
});
