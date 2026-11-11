/// <reference types="vitest/globals" />
/**
 * Error classes and the shared API error parser.
 *
 * Every error class parses API responses with the same parser: the server code and
 * message are exposed verbatim, details stay raw, retryAfter / requestId are exposed,
 * and bodies that are not in the standard shape fall back to HTTP_<status>.
 */

import {
  CapsaraError,
  parseApiError,
  parseErrorResponse,
  type ApiErrorResponse,
  type AxiosLikeError,
} from '../../../src/errors/capsara-error.js';
import { CapsaraCapsaError } from '../../../src/errors/capsa-error.js';
import { CapsaraAccountError } from '../../../src/errors/account-error.js';
import { CapsaraAuthError } from '../../../src/errors/auth-error.js';
import { CapsaraAuditError } from '../../../src/errors/audit-error.js';

function apiError(status: number, data: unknown, extra: Partial<ApiErrorResponse> = {}): AxiosLikeError {
  return { response: { status, data, ...extra }, message: `Request failed with status code ${status}` };
}

function standardBody(code: string, message: string, details?: unknown, more: Record<string, unknown> = {}) {
  return { error: { code, message, ...(details !== undefined && { details }), ...more } };
}

const errorClasses = [
  { name: 'CapsaraError', cls: CapsaraError, fallback: 'UNKNOWN_ERROR' },
  { name: 'CapsaraCapsaError', cls: CapsaraCapsaError, fallback: 'CAPSA_ERROR' },
  { name: 'CapsaraAccountError', cls: CapsaraAccountError, fallback: 'ACCOUNT_ERROR' },
  { name: 'CapsaraAuthError', cls: CapsaraAuthError, fallback: 'AUTH_ERROR' },
  { name: 'CapsaraAuditError', cls: CapsaraAuditError, fallback: 'AUDIT_ERROR' },
] as const;

describe('parseErrorResponse', () => {
  it('reads code, message and details from the standard shape', () => {
    const parsed = parseErrorResponse({
      status: 404,
      data: standardBody('ENVELOPE_NOT_FOUND', 'Capsa not found', { capsaId: 'capsa_1' }),
    });
    expect(parsed).toMatchObject({
      code: 'ENVELOPE_NOT_FOUND',
      message: 'Capsa not found',
      statusCode: 404,
      details: { capsaId: 'capsa_1' },
    });
  });

  it('keeps array details raw (validation issues)', () => {
    const issues = [{ path: 'limit', message: 'Too big' }];
    const parsed = parseErrorResponse({ status: 400, data: standardBody('VALIDATION_ERROR', 'Invalid', issues) });
    expect(parsed.details).toEqual(issues);
  });

  it('keeps string details raw', () => {
    const parsed = parseErrorResponse({ status: 400, data: standardBody('X', 'Y', 'free text') });
    expect(parsed.details).toBe('free text');
  });

  it('parses a JSON body that arrived as a string', () => {
    const parsed = parseErrorResponse({
      status: 410,
      data: JSON.stringify(standardBody('ENVELOPE_EXPIRED', 'Expired', { status: 'expired', expiredAt: '2026-01-01T00:00:00.000Z' })),
    });
    expect(parsed.code).toBe('ENVELOPE_EXPIRED');
    expect(parsed.details).toEqual({ status: 'expired', expiredAt: '2026-01-01T00:00:00.000Z' });
  });

  it('parses a JSON body that arrived as a Buffer', () => {
    const parsed = parseErrorResponse({ status: 409, data: Buffer.from(JSON.stringify(standardBody('ENVELOPE_ALREADY_EXISTS', 'Exists'))) });
    expect(parsed.code).toBe('ENVELOPE_ALREADY_EXISTS');
  });

  it('parses a JSON body that arrived as an ArrayBuffer', () => {
    const bytes = Buffer.from(JSON.stringify(standardBody('FILE_NOT_FOUND', 'No file')));
    const arrayBuffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length);
    expect(parseErrorResponse({ status: 404, data: arrayBuffer }).code).toBe('FILE_NOT_FOUND');
  });

  it('falls back to HTTP_<status> and the reason phrase for a non-JSON body', () => {
    const parsed = parseErrorResponse({ status: 502, data: '<html>Bad Gateway</html>' });
    expect(parsed.code).toBe('HTTP_502');
    expect(parsed.message).toBe('Bad Gateway');
    expect(parsed.details).toBeUndefined();
  });

  it('prefers statusText over the standard reason phrase', () => {
    const parsed = parseErrorResponse({ status: 500, statusText: 'Server Melted', data: null });
    expect(parsed.message).toBe('Server Melted');
  });

  it('uses a generic message for a status with no reason phrase', () => {
    expect(parseErrorResponse({ status: 599, data: undefined }).message).toBe('HTTP 599');
  });

  it('falls back when error is a string rather than an object', () => {
    const parsed = parseErrorResponse({ status: 401, data: { error: 'Unauthorized' } });
    expect(parsed.code).toBe('HTTP_401');
    expect(parsed.message).toBe('Unauthorized');
  });

  it('falls back when the body is an array or a number', () => {
    expect(parseErrorResponse({ status: 400, data: [1, 2] }).code).toBe('HTTP_400');
    expect(parseErrorResponse({ status: 400, data: 42 }).code).toBe('HTTP_400');
  });

  it('falls back when the error object has no code', () => {
    const parsed = parseErrorResponse({ status: 403, data: { error: { message: 'Nope' } } });
    expect(parsed.code).toBe('HTTP_403');
  });

  it('uses the reason phrase when the standard shape has no message', () => {
    const parsed = parseErrorResponse({ status: 404, data: { error: { code: 'ENVELOPE_NOT_FOUND' } } });
    expect(parsed.code).toBe('ENVELOPE_NOT_FOUND');
    expect(parsed.message).toBe('Not Found');
  });

  it('reads retryAfter from the error body', () => {
    const parsed = parseErrorResponse({ status: 429, data: standardBody('RATE_LIMIT_EXCEEDED', 'Slow down', undefined, { retryAfter: 30 }) });
    expect(parsed.retryAfter).toBe(30);
  });

  it('falls back to the Retry-After header (any case)', () => {
    const parsed = parseErrorResponse({
      status: 429,
      headers: { 'Retry-After': '12' },
      data: standardBody('TOO_MANY_FAILURES', 'Too many failures'),
    });
    expect(parsed.retryAfter).toBe(12);
  });

  it('accepts a numeric Retry-After header and ignores an HTTP-date one', () => {
    expect(parseErrorResponse({ status: 503, headers: { 'retry-after': 5 }, data: null }).retryAfter).toBe(5);
    expect(parseErrorResponse({ status: 503, headers: { 'retry-after': 'Wed, 21 Oct 2015 07:28:00 GMT' }, data: null }).retryAfter).toBeUndefined();
  });

  it('ignores a negative or non-numeric body retryAfter', () => {
    expect(parseErrorResponse({ status: 429, data: standardBody('X', 'Y', undefined, { retryAfter: -1 }) }).retryAfter).toBeUndefined();
    expect(parseErrorResponse({ status: 429, data: standardBody('X', 'Y', undefined, { retryAfter: 'soon' }) }).retryAfter).toBeUndefined();
  });

  it('reads requestId from the error object or the top level', () => {
    expect(parseErrorResponse({ status: 500, data: standardBody('X', 'Y', undefined, { requestId: 'req-1' }) }).requestId).toBe('req-1');
    expect(parseErrorResponse({ status: 500, data: { ...standardBody('X', 'Y'), requestId: 'req-2' } }).requestId).toBe('req-2');
  });

  it('ignores a non-string requestId', () => {
    expect(parseErrorResponse({ status: 500, data: standardBody('X', 'Y', undefined, { requestId: 7 }) }).requestId).toBeUndefined();
  });

  it('returns the decoded body on the response', () => {
    const parsed = parseErrorResponse({ status: 400, data: JSON.stringify(standardBody('X', 'Y')) });
    expect(parsed.response?.data).toEqual(standardBody('X', 'Y'));
  });
});

describe('parseApiError', () => {
  it('parses an axios error with a response', () => {
    expect(parseApiError(apiError(403, standardBody('ACCESS_DENIED', 'Denied')), 'X').code).toBe('ACCESS_DENIED');
  });

  it('maps a request without a response to NETWORK_ERROR', () => {
    const parsed = parseApiError({ request: {}, message: 'ECONNREFUSED' }, 'X');
    expect(parsed).toMatchObject({ code: 'NETWORK_ERROR', statusCode: 0, details: { originalError: 'ECONNREFUSED' } });
  });

  it('reports an unknown network error when there is no message', () => {
    expect(parseApiError({ request: {} }, 'X').details).toEqual({ originalError: 'Unknown network error' });
  });

  it('uses the fallback code for a plain Error', () => {
    const parsed = parseApiError(new Error('boom'), 'CAPSA_ERROR');
    expect(parsed).toMatchObject({ code: 'CAPSA_ERROR', statusCode: 0, message: 'boom' });
  });

  it('handles a thrown string', () => {
    expect(parseApiError('just text', 'X').message).toBe('just text');
  });

  it('handles null and undefined', () => {
    expect(parseApiError(null, 'X')).toMatchObject({ code: 'X', message: 'An unknown error occurred' });
    expect(parseApiError(undefined, 'X').details).toEqual({ originalError: 'Unknown error' });
  });

  it('copies an existing SDK error', () => {
    const source = new CapsaraAuthError('Token revoked', 'TOKEN_REVOKED', 401, ['a'], undefined, { retryAfter: 3, requestId: 'r' });
    expect(parseApiError(source, 'X')).toEqual({
      message: 'Token revoked',
      code: 'TOKEN_REVOKED',
      statusCode: 401,
      details: ['a'],
      retryAfter: 3,
      requestId: 'r',
    });
  });

  it('copies an SDK error without extras', () => {
    const parsed = parseApiError(new CapsaraError('m', 'C', 400), 'X');
    expect(parsed).not.toHaveProperty('retryAfter');
    expect(parsed).not.toHaveProperty('requestId');
  });
});

describe.each(errorClasses)('$name.fromApiError', ({ name, cls, fallback }) => {
  it('exposes the server code and message verbatim', () => {
    const error = cls.fromApiError(apiError(404, standardBody('ENVELOPE_NOT_FOUND', 'Envelope not found')));
    expect(error).toBeInstanceOf(cls);
    expect(error.name).toBe(name);
    expect(error.code).toBe('ENVELOPE_NOT_FOUND');
    expect(error.message).toBe('Envelope not found');
    expect(error.statusCode).toBe(404);
  });

  it('keeps details raw', () => {
    const issues = [{ path: 'x', message: 'bad' }];
    expect(cls.fromApiError(apiError(400, standardBody('VALIDATION_ERROR', 'Invalid', issues))).details).toEqual(issues);
  });

  it('exposes retryAfter and requestId', () => {
    const error = cls.fromApiError(apiError(503, standardBody('SERVICE_UNAVAILABLE', 'Busy', undefined, { retryAfter: 2, requestId: 'req-9' })));
    expect(error.retryAfter).toBe(2);
    expect(error.requestId).toBe('req-9');
  });

  it('tolerates a non-JSON body', () => {
    const error = cls.fromApiError(apiError(504, 'upstream timed out'));
    expect(error.code).toBe('HTTP_504');
    expect(error.message).toBe('Gateway Timeout');
  });

  it('maps network errors', () => {
    const error = cls.fromApiError({ request: {}, message: 'socket hang up' });
    expect(error.code).toBe('NETWORK_ERROR');
    expect(error.statusCode).toBe(0);
  });

  it('uses its own fallback code for client-side errors', () => {
    const error = cls.fromApiError(new Error('local failure'));
    expect(error.code).toBe(fallback);
    expect(error.statusCode).toBe(0);
  });

  it('returns the same instance when given its own type', () => {
    const original = cls.fromApiError(new Error('x'));
    expect(cls.fromApiError(original)).toBe(original);
  });

  it('stores a sanitized response', () => {
    const error = cls.fromApiError(apiError(400, standardBody('X', 'Y'), {
      statusText: 'Bad Request',
      headers: { 'content-type': 'application/json', authorization: 'Bearer secret' },
    }));
    expect(error.response?.status).toBe(400);
    expect(error.response?.headers).toEqual({ 'content-type': 'application/json' });
  });
});

describe('cross-type conversion', () => {
  it('re-wraps another non-auth SDK error type, keeping code, status, details and extras', () => {
    const audit = new CapsaraAuditError('Rate limited', 'RATE_LIMITED', 429, { a: 1 }, undefined, { retryAfter: 4 });
    const capsa = CapsaraCapsaError.fromApiError(audit);
    expect(capsa).toBeInstanceOf(CapsaraCapsaError);
    expect(capsa.code).toBe('RATE_LIMITED');
    expect(capsa.statusCode).toBe(429);
    expect(capsa.details).toEqual({ a: 1 });
    expect(capsa.retryAfter).toBe(4);
  });

  it.each([
    ['capsa', CapsaraCapsaError.fromApiError],
    ['audit', CapsaraAuditError.fromApiError],
    ['account', CapsaraAccountError.fromApiError],
  ])('passes an auth error through the %s conversion unchanged', (_name, convert) => {
    const auth = new CapsaraAuthError('Refresh failed', 'INVALID_REFRESH_TOKEN', 401, { a: 1 });
    expect(convert(auth)).toBe(auth);
  });

  it('CapsaraError.fromApiError returns any SDK error unchanged', () => {
    const audit = CapsaraAuditError.missingDetails();
    expect(CapsaraError.fromApiError(audit)).toBe(audit);
  });
});

describe('CapsaraError', () => {
  it('constructs with all fields', () => {
    const error = new CapsaraError('msg', 'CODE', 418, { x: 1 }, { status: 418, data: { a: 1 } }, { retryAfter: 1, requestId: 'r' });
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('msg');
    expect(error.code).toBe('CODE');
    expect(error.statusCode).toBe(418);
    expect(error.details).toEqual({ x: 1 });
    expect(error.retryAfter).toBe(1);
    expect(error.requestId).toBe('r');
    expect(error.response).toEqual({ status: 418, statusText: undefined, headers: undefined, data: { a: 1 } });
    expect(error.stack).toBeDefined();
  });

  it('leaves optional fields unset', () => {
    const error = new CapsaraError('m', 'C', 0);
    expect(error.details).toBeUndefined();
    expect(error.retryAfter).toBeUndefined();
    expect(error.requestId).toBeUndefined();
    expect(error.response).toBeUndefined();
  });

  it('keeps only safe headers, joining array values', () => {
    const error = new CapsaraError('m', 'C', 429, undefined, {
      status: 429,
      headers: {
        'Retry-After': 10,
        'X-Request-Id': ['a', 'b'],
        'set-cookie': 'secret',
        'content-type': undefined,
        authorization: 'Bearer token',
      },
    });
    expect(error.response?.headers).toEqual({ 'Retry-After': '10', 'X-Request-Id': 'a, b' });
  });

  it('truncates large object bodies', () => {
    const error = new CapsaraError('m', 'C', 500, undefined, { status: 500, data: { blob: 'x'.repeat(5000) } });
    expect(typeof error.response?.data).toBe('string');
    expect((error.response?.data as string).endsWith('...[truncated]')).toBe(true);
    expect((error.response?.data as string).length).toBe(1024 + '...[truncated]'.length);
  });

  it('truncates large string bodies', () => {
    const error = new CapsaraError('m', 'C', 500, undefined, { status: 500, data: 'y'.repeat(2000) });
    expect((error.response?.data as string).endsWith('...[truncated]')).toBe(true);
  });

  it('keeps small and empty bodies as-is', () => {
    expect(new CapsaraError('m', 'C', 500, undefined, { status: 500, data: 'short' }).response?.data).toBe('short');
    expect(new CapsaraError('m', 'C', 500, undefined, { status: 500, data: null }).response?.data).toBeNull();
  });

  it('serializes to JSON with extras only when present', () => {
    const plain = new CapsaraError('m', 'C', 400, ['d']).toJSON();
    expect(plain).toEqual({ name: 'CapsaraError', message: 'm', code: 'C', statusCode: 400, details: ['d'] });

    const full = new CapsaraError('m', 'C', 429, undefined, { status: 429, data: {} }, { retryAfter: 9, requestId: 'q' }).toJSON();
    expect(full).toMatchObject({ retryAfter: 9, requestId: 'q', response: { status: 429 } });
  });
});

describe('subclass specifics', () => {
  it('CapsaraCapsaError.downloadFailed wraps a client-side cause', () => {
    const cause = new Error('bad tag');
    const error = CapsaraCapsaError.downloadFailed('capsa_1', 'file_1.enc', cause);
    expect(error.code).toBe('DOWNLOAD_FAILED');
    expect(error.statusCode).toBe(0);
    expect(error.message).toContain('file_1.enc');
    expect(error.details).toEqual({ capsaId: 'capsa_1', fileId: 'file_1.enc', originalError: 'bad tag' });
    expect(error.cause).toBe(cause);
  });

  it('CapsaraCapsaError.downloadFailed accepts a non-Error cause', () => {
    const error = CapsaraCapsaError.downloadFailed('c', 'f', 'oops');
    expect(error.details).toMatchObject({ originalError: 'oops' });
    expect(error.cause).toBeUndefined();
  });

  it('CapsaraAuditError.missingDetails is a client-side error', () => {
    const error = CapsaraAuditError.missingDetails();
    expect(error.code).toBe('MISSING_DETAILS');
    expect(error.statusCode).toBe(0);
  });

  it.each(errorClasses)('$name is an instance of CapsaraError and Error', ({ cls }) => {
    const error = cls.fromApiError(new Error('x'));
    expect(error).toBeInstanceOf(CapsaraError);
    expect(error).toBeInstanceOf(Error);
  });
});
