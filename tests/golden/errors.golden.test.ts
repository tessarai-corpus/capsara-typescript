/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Error Classes
 * Tests fromApiError (server codes verbatim, raw details, retryAfter, non-JSON bodies),
 * network error, generic error, client-side factories, toJSON, instanceof hierarchy.
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
      expect(error.statusCode).toBe(0);
      expect(error.message).toBe('Something went wrong');
    });

    it('should fall back to HTTP_<status> for a non-JSON body', () => {
      const error = CapsaraError.fromApiError({ response: { status: 502, data: '<html>bad gateway</html>' } });

      expect(error.code).toBe('HTTP_502');
      expect(error.statusCode).toBe(502);
      expect(error.message).toBe('Bad Gateway');
    });

    it('should keep array details and expose retryAfter', () => {
      const error = CapsaraError.fromApiError({
        response: {
          status: 429,
          data: { error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Slow down', details: [{ path: 'x' }], retryAfter: 30 } },
        },
      });

      expect(error.details).toEqual([{ path: 'x' }]);
      expect(error.retryAfter).toBe(30);
    });
  });

  describe('CapsaraAuthError', () => {
    it('should map AUTHENTICATION_FAILED code from API', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 401,
          data: { error: { code: 'AUTHENTICATION_FAILED', message: 'Invalid party ID or password' } },
        },
      };

      const error = CapsaraAuthError.fromApiError(axiosError);
      expect(error.name).toBe('CapsaraAuthError');
      expect(error.code).toBe('AUTHENTICATION_FAILED');
      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Invalid party ID or password');
    });
  });

  describe('CapsaraCapsaError', () => {
    it('should create downloadFailed error with context', () => {
      const cause = new Error('Blob timeout');
      const error = CapsaraCapsaError.downloadFailed('capsa_1', 'file_2.enc', cause);

      expect(error.code).toBe('DOWNLOAD_FAILED');
      expect(error.message).toContain('capsa_1');
      expect(error.message).toContain('file_2.enc');
      expect(error.message).toContain('Blob timeout');
      expect(error.details).toMatchObject({ capsaId: 'capsa_1' });
    });

    it('should expose ENVELOPE_NOT_FOUND verbatim', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 404,
          data: { error: { code: 'ENVELOPE_NOT_FOUND', message: 'Envelope not found' } },
        },
      };

      const error = CapsaraCapsaError.fromApiError(axiosError);
      expect(error.code).toBe('ENVELOPE_NOT_FOUND');
      expect(error.message).toBe('Envelope not found');
      expect(error.statusCode).toBe(404);
    });

    it('should expose 410 ENVELOPE_EXPIRED with its details', () => {
      const error = CapsaraCapsaError.fromApiError({
        response: {
          status: 410,
          data: {
            error: {
              code: 'ENVELOPE_EXPIRED',
              message: 'Capsa has expired',
              details: { status: 'expired', expiredAt: '2026-01-01T00:00:00.000Z' },
            },
          },
        },
      });

      expect(error.code).toBe('ENVELOPE_EXPIRED');
      expect(error.statusCode).toBe(410);
      expect(error.details).toEqual({ status: 'expired', expiredAt: '2026-01-01T00:00:00.000Z' });
    });
  });

  describe('CapsaraAuditError factory methods', () => {
    it('should create missingDetails error', () => {
      const error = CapsaraAuditError.missingDetails();

      expect(error).toBeInstanceOf(CapsaraAuditError);
      expect(error.code).toBe('MISSING_DETAILS');
      expect(error.statusCode).toBe(0);
    });

    it('should expose ENVELOPE_NOT_FOUND verbatim', () => {
      const axiosError: AxiosLikeError = {
        response: {
          status: 404,
          data: { error: { code: 'ENVELOPE_NOT_FOUND', message: 'Envelope not found' } },
        },
      };

      const error = CapsaraAuditError.fromApiError(axiosError);
      expect(error.code).toBe('ENVELOPE_NOT_FOUND');
    });
  });

  describe('CapsaraAccountError', () => {
    it('should expose key registration codes verbatim', () => {
      const error = CapsaraAccountError.fromApiError({
        response: { status: 400, data: { error: { code: 'PUBLIC_KEY_TOO_SMALL', message: 'Key must be 4096 bits' } } },
      });

      expect(error.name).toBe('CapsaraAccountError');
      expect(error).toBeInstanceOf(CapsaraError);
      expect(error.code).toBe('PUBLIC_KEY_TOO_SMALL');
      expect(error.statusCode).toBe(400);
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
      const error = CapsaraAuthError.fromApiError(new Error('x'));
      expect(error.name).toBe('CapsaraAuthError');
      expect(error instanceof CapsaraError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it('CapsaraCapsaError should be instanceof CapsaraError and Error', () => {
      const error = CapsaraCapsaError.fromApiError(new Error('x'));

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
      const error = CapsaraAccountError.fromApiError(new Error('x'));

      expect(error.name).toBe('CapsaraAccountError');
      expect(error instanceof CapsaraError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });
  });
});
