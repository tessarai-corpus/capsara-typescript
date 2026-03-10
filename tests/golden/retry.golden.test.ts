/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Retry Interceptor
 * Tests exponential backoff, 429 Retry-After (body/header/date),
 * max delay cap, non-retryable status, retry count tracking.
 */

import type { AxiosError, AxiosInstance, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { addRetryInterceptor, type RetryLogger } from '../../src/internal/config/retry-interceptor.js';

function createMockAxiosInstance() {
  let responseErrorHandler: ((error: AxiosError) => Promise<AxiosResponse>) | null = null;
  let responseSuccessHandler: ((response: AxiosResponse) => AxiosResponse) | null = null;

  const mockInstance = {
    interceptors: {
      request: { use: vi.fn() },
      response: {
        use: vi.fn((onFulfilled: (r: AxiosResponse) => AxiosResponse, onRejected: (e: AxiosError) => Promise<AxiosResponse>) => {
          responseSuccessHandler = onFulfilled;
          responseErrorHandler = onRejected;
        }),
      },
    },
    request: vi.fn(),
  } as unknown as AxiosInstance;

  return {
    instance: mockInstance,
    getErrorHandler: () => responseErrorHandler!,
    getSuccessHandler: () => responseSuccessHandler!,
  };
}

function createAxiosError(
  status: number,
  responseData?: unknown,
  headers?: Record<string, string>
): AxiosError {
  const error = new Error(`Request failed with status ${status}`) as AxiosError;
  error.isAxiosError = true;
  error.response = {
    status,
    statusText: 'Error',
    headers: headers || {},
    data: responseData,
    config: {} as InternalAxiosRequestConfig,
  };
  error.config = {
    url: '/test',
    method: 'get',
    headers: {},
  } as InternalAxiosRequestConfig;
  return error;
}

describe('Golden: Retry', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('should use exponential backoff: base * 2^retryCount', async () => {
    const { instance, getErrorHandler } = createMockAxiosInstance();
    const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 200 });
    (instance as { request: typeof mockRequest }).request = mockRequest;

    addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 1000, maxDelay: 60000 });
    const handler = getErrorHandler();

    const error = createAxiosError(503);
    const promise = handler(error);

    // First retry delay: 1000 * 2^0 = 1000ms (+ up to 30% jitter)
    // Should not have retried at 500ms
    await vi.advanceTimersByTimeAsync(500);
    expect(mockRequest).not.toHaveBeenCalled();

    // Should have retried by 1500ms (base + max jitter)
    await vi.advanceTimersByTimeAsync(1000);
    await promise;
    expect(mockRequest).toHaveBeenCalledTimes(1);
  });

  it('should use Retry-After from response body (error.retryAfter)', async () => {
    const { instance, getErrorHandler } = createMockAxiosInstance();
    const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 200 });
    (instance as { request: typeof mockRequest }).request = mockRequest;

    addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100, maxDelay: 60000 });
    const handler = getErrorHandler();

    const error = createAxiosError(429, { error: { retryAfter: 2 } });
    const promise = handler(error);

    // Server says wait 2 seconds (2000ms)
    await vi.advanceTimersByTimeAsync(1500);
    expect(mockRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1000);
    await promise;
    expect(mockRequest).toHaveBeenCalledTimes(1);
  });

  it('should use Retry-After from HTTP header (seconds)', async () => {
    const { instance, getErrorHandler } = createMockAxiosInstance();
    const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 200 });
    (instance as { request: typeof mockRequest }).request = mockRequest;

    addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100, maxDelay: 60000 });
    const handler = getErrorHandler();

    const error = createAxiosError(429, {}, { 'retry-after': '3' });
    const promise = handler(error);

    // Header says 3 seconds
    await vi.advanceTimersByTimeAsync(2500);
    expect(mockRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1000);
    await promise;
    expect(mockRequest).toHaveBeenCalledTimes(1);
  });

  it('should use Retry-After from HTTP header (date format)', async () => {
    const { instance, getErrorHandler } = createMockAxiosInstance();
    const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 200 });
    (instance as { request: typeof mockRequest }).request = mockRequest;

    const now = new Date('2025-01-01T12:00:00Z');
    vi.setSystemTime(now);

    const futureDate = new Date(now.getTime() + 2000); // 2 seconds from now

    addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100, maxDelay: 60000 });
    const handler = getErrorHandler();

    const error = createAxiosError(429, {}, { 'retry-after': futureDate.toUTCString() });
    const promise = handler(error);

    await vi.runAllTimersAsync();
    await promise;
    expect(mockRequest).toHaveBeenCalledTimes(1);
  });

  it('should cap retry delay at maxDelay', async () => {
    const { instance, getErrorHandler } = createMockAxiosInstance();
    const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 200 });
    (instance as { request: typeof mockRequest }).request = mockRequest;

    // maxDelay = 2000, but Retry-After header says 60 seconds
    addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100, maxDelay: 2000 });
    const handler = getErrorHandler();

    const error = createAxiosError(429, {}, { 'retry-after': '60' });
    const promise = handler(error);

    // Should be capped at 2000ms, not 60000ms
    await vi.advanceTimersByTimeAsync(2500);
    await promise;
    expect(mockRequest).toHaveBeenCalledTimes(1);
  });

  it('should not retry non-retryable status codes (400, 401, 404, 500)', async () => {
    const { instance, getErrorHandler } = createMockAxiosInstance();
    const mockRequest = vi.fn();
    (instance as { request: typeof mockRequest }).request = mockRequest;

    addRetryInterceptor(instance, { maxRetries: 3 });
    const handler = getErrorHandler();

    for (const status of [400, 401, 403, 404, 500]) {
      const error = createAxiosError(status);
      await expect(handler(error)).rejects.toThrow();
    }

    expect(mockRequest).not.toHaveBeenCalled();
  });

  it('should track retry count and stop after maxRetries', async () => {
    const { instance, getErrorHandler } = createMockAxiosInstance();
    let errorHandler: ((error: AxiosError) => Promise<AxiosResponse>) | null = null;

    addRetryInterceptor(instance, { maxRetries: 2, baseDelay: 100, maxDelay: 500 });
    errorHandler = getErrorHandler();

    let callCount = 0;
    const mockRequest = vi.fn().mockImplementation(async (config) => {
      callCount++;
      const retryError = createAxiosError(503);
      retryError.config = config;
      return errorHandler!(retryError);
    });
    (instance as { request: typeof mockRequest }).request = mockRequest;

    const error = createAxiosError(503);
    const promise = errorHandler!(error);
    await vi.runAllTimersAsync();

    await expect(promise).rejects.toThrow();
    expect(callCount).toBe(2); // 2 retries (maxRetries)
  });

  it('should log retry attempts when logging is enabled', async () => {
    const { instance, getErrorHandler } = createMockAxiosInstance();
    const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 200 });
    (instance as { request: typeof mockRequest }).request = mockRequest;

    const logger: RetryLogger = { log: vi.fn() };

    addRetryInterceptor(instance, {
      maxRetries: 3,
      baseDelay: 100,
      enableLogging: true,
      logger,
    });
    const handler = getErrorHandler();

    const error = createAxiosError(503);
    const promise = handler(error);
    await vi.runAllTimersAsync();
    await promise;

    expect(logger.log).toHaveBeenCalled();
    const logMsg = (logger.log as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as string;
    expect(logMsg).toContain('[Capsara SDK]');
    expect(logMsg).toContain('Retry attempt');
  });
});
