/**
 * Tests for retry-interceptor.ts - Axios retry interceptor
 * @file tests/unit/internal/config/retry-interceptor.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { AxiosError, AxiosInstance, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { addRetryInterceptor, type RetryLogger } from '../../../../src/internal/config/retry-interceptor.js';

/**
 * Helper to create a mock axios instance with interceptors
 */
function createMockAxiosInstance() {
  let responseErrorHandler: ((error: AxiosError) => Promise<AxiosResponse>) | null = null;
  let responseSuccessHandler: ((response: AxiosResponse) => AxiosResponse) | null = null;

  const mockInstance = {
    interceptors: {
      request: { use: vi.fn() },
      response: {
        use: vi.fn((onFulfilled: (response: AxiosResponse) => AxiosResponse, onRejected: (error: AxiosError) => Promise<AxiosResponse>) => {
          responseSuccessHandler = onFulfilled;
          responseErrorHandler = onRejected;
        }),
      },
    },
    request: vi.fn(),
  } as unknown as AxiosInstance;

  return {
    instance: mockInstance,
    getResponseErrorHandler: () => responseErrorHandler,
    getResponseSuccessHandler: () => responseSuccessHandler,
  };
}

/**
 * Helper to create a mock AxiosError
 */
function createMockAxiosError(
  status: number,
  responseData?: unknown,
  headers?: Record<string, string>,
  config?: Partial<InternalAxiosRequestConfig>
): AxiosError {
  const error = new Error(`Request failed with status code ${status}`) as AxiosError;
  error.isAxiosError = true;
  error.response = {
    status,
    statusText: status === 503 ? 'Service Unavailable' : status === 429 ? 'Too Many Requests' : 'Error',
    headers: headers || {},
    data: responseData,
    config: {} as InternalAxiosRequestConfig,
  };
  error.config = {
    url: '/test',
    method: 'get',
    headers: {},
    ...config,
  } as InternalAxiosRequestConfig;
  return error;
}

/**
 * Helper to create a mock network error (no response)
 */
function createMockNetworkError(config?: Partial<InternalAxiosRequestConfig>): AxiosError {
  const error = new Error('Network Error') as AxiosError;
  error.isAxiosError = true;
  error.response = undefined;
  error.config = config as InternalAxiosRequestConfig;
  return error;
}

describe('retry-interceptor', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('addRetryInterceptor', () => {
    it('should add response interceptor to axios instance', () => {
      const { instance } = createMockAxiosInstance();

      addRetryInterceptor(instance);

      expect(instance.interceptors.response.use).toHaveBeenCalledOnce();
    });

    it('should pass through successful responses', async () => {
      const { instance, getResponseSuccessHandler } = createMockAxiosInstance();

      addRetryInterceptor(instance);

      const successHandler = getResponseSuccessHandler();
      const mockResponse = { data: 'test', status: 200 } as AxiosResponse;

      const result = successHandler!(mockResponse);
      expect(result).toBe(mockResponse);
    });
  });

  describe('retry behavior for 503 errors', () => {
    it('should retry on 503 Service Unavailable', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100 });

      const error = createMockAxiosError(503);
      const errorHandler = getResponseErrorHandler();

      // Start the retry
      const retryPromise = errorHandler!(error);

      // Advance timers to allow retry delay
      await vi.runAllTimersAsync();

      const result = await retryPromise;
      expect(result.status).toBe(200);
      expect(mockRequest).toHaveBeenCalled();
    });

    it('should increment retry count on each attempt', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      let callCount = 0;
      let errorHandler: ((error: AxiosError) => Promise<AxiosResponse>) | null = null;

      // Store the error handler for recursive calls
      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100 });
      errorHandler = getResponseErrorHandler();

      // Mock request that simulates axios calling the interceptor again on error
      const mockRequest = vi.fn().mockImplementation(async (config) => {
        callCount++;
        if (callCount < 3) {
          // Simulate axios calling interceptor on error
          const retryError = createMockAxiosError(503);
          retryError.config = config;
          // Call the error handler recursively (simulates axios interceptor behavior)
          return errorHandler!(retryError);
        }
        return { data: 'success', status: 200 };
      });
      instance.request = mockRequest;

      const error = createMockAxiosError(503);
      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();

      const result = await retryPromise;
      expect(result.status).toBe(200);
      expect(callCount).toBe(3); // 3 request calls total (initial retry + 2 more retries)
    });

    it('should stop retrying after maxRetries exceeded', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockImplementation((config) => {
        const retryError = createMockAxiosError(503);
        retryError.config = config;
        return Promise.reject(retryError);
      });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 2, baseDelay: 100 });

      const error = createMockAxiosError(503);
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);
      const rejection = expect(retryPromise).rejects.toThrow();
      await vi.runAllTimersAsync();

      await rejection;
    });
  });

  describe('retry behavior for 429 errors', () => {
    it('should retry on 429 with Retry-After header', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100 });

      const error = createMockAxiosError(429, {}, { 'retry-after': '1' });
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();

      const result = await retryPromise;
      expect(result.status).toBe(200);
    });

    it('should retry 429 without Retry-After using exponential backoff', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 1000 });

      const retryPromise = getResponseErrorHandler()!(createMockAxiosError(429));

      await vi.advanceTimersByTimeAsync(999);
      expect(mockRequest).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(301);
      await expect(retryPromise).resolves.toMatchObject({ status: 200 });
      expect(mockRequest).toHaveBeenCalledOnce();
    });
  });

  describe('non-retryable errors', () => {
    it('should not retry on 400 Bad Request', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn();
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3 });

      const error = createMockAxiosError(400);
      const errorHandler = getResponseErrorHandler();

      await expect(errorHandler!(error)).rejects.toThrow();
      expect(mockRequest).not.toHaveBeenCalled();
    });

    it('should not retry on 401 Unauthorized', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn();
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3 });

      const error = createMockAxiosError(401);
      const errorHandler = getResponseErrorHandler();

      await expect(errorHandler!(error)).rejects.toThrow();
      expect(mockRequest).not.toHaveBeenCalled();
    });

    it('should not retry on 403 Forbidden', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn();
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3 });

      const error = createMockAxiosError(403);
      const errorHandler = getResponseErrorHandler();

      await expect(errorHandler!(error)).rejects.toThrow();
      expect(mockRequest).not.toHaveBeenCalled();
    });

    it('should not retry on 404 Not Found', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn();
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3 });

      const error = createMockAxiosError(404);
      const errorHandler = getResponseErrorHandler();

      await expect(errorHandler!(error)).rejects.toThrow();
      expect(mockRequest).not.toHaveBeenCalled();
    });

    it('should not retry on 500 Internal Server Error', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn();
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3 });

      const error = createMockAxiosError(500);
      const errorHandler = getResponseErrorHandler();

      await expect(errorHandler!(error)).rejects.toThrow();
      expect(mockRequest).not.toHaveBeenCalled();
    });

    it('should not retry a cancelled request', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn();
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3 });

      const error = createMockNetworkError({ url: '/test', method: 'get', headers: {} } as Partial<InternalAxiosRequestConfig>);
      error.code = 'ERR_CANCELED';

      await expect(getResponseErrorHandler()!(error)).rejects.toBe(error);
      expect(mockRequest).not.toHaveBeenCalled();
    });

    it('should not retry when config is missing', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn();
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3 });

      const error = createMockAxiosError(503);
      error.config = undefined;
      const errorHandler = getResponseErrorHandler();

      await expect(errorHandler!(error)).rejects.toThrow();
      expect(mockRequest).not.toHaveBeenCalled();
    });
  });

  describe('Retry-After header handling', () => {
    it('should use Retry-After header when specified in seconds', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100, maxDelay: 60000 });

      const error = createMockAxiosError(429, {}, { 'retry-after': '5' });
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);

      // Verify delay is used (5 seconds = 5000ms)
      await vi.advanceTimersByTimeAsync(4000);
      expect(mockRequest).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(2000);
      await retryPromise;
      expect(mockRequest).toHaveBeenCalled();
    });

    it('should use Retry-After header when specified as HTTP date', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      // Set a specific time for predictable date parsing
      const now = new Date('2024-01-01T12:00:00Z');
      vi.setSystemTime(now);

      const futureDate = new Date(now.getTime() + 3000); // 3 seconds in the future

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100, maxDelay: 60000 });

      const error = createMockAxiosError(429, {}, { 'retry-after': futureDate.toUTCString() });
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();

      await retryPromise;
      expect(mockRequest).toHaveBeenCalled();
    });

    it('should cap a server Retry-After at maxDelay', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100, maxDelay: 5000 });

      const retryPromise = getResponseErrorHandler()!(createMockAxiosError(429, {}, { 'retry-after': '60' }));

      await vi.advanceTimersByTimeAsync(4999);
      expect(mockRequest).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      await retryPromise;
      expect(mockRequest).toHaveBeenCalledOnce();
    });

    it('should cap a server hint at the default 30 seconds', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance);

      const retryPromise = getResponseErrorHandler()!(createMockAxiosError(503, { error: { retryAfter: 120 } }));

      await vi.advanceTimersByTimeAsync(29_999);
      expect(mockRequest).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      await retryPromise;
      expect(mockRequest).toHaveBeenCalledOnce();
    });
  });

  describe('retryAfter field in response body', () => {
    it('should use retryAfter from response body error object', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100, maxDelay: 60000 });

      const responseData = {
        error: {
          retryAfter: 2, // 2 seconds
          message: 'Rate limited',
        },
      };
      const error = createMockAxiosError(429, responseData);
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);

      // Verify delay is used (2 seconds = 2000ms)
      await vi.advanceTimersByTimeAsync(1500);
      expect(mockRequest).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(1000);
      await retryPromise;
      expect(mockRequest).toHaveBeenCalled();
    });

    it('should prefer response body retryAfter over header', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100, maxDelay: 60000 });

      const responseData = {
        error: {
          retryAfter: 1, // 1 second from body
        },
      };
      // Header says 10 seconds, body says 1 second - body should win
      const error = createMockAxiosError(429, responseData, { 'retry-after': '10' });
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();

      await retryPromise;
      expect(mockRequest).toHaveBeenCalled();
    });
  });

  describe('exponential backoff', () => {
    it('should use exponential backoff when no server delay is provided', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      let callCount = 0;
      let errorHandler: ((error: AxiosError) => Promise<AxiosResponse>) | null = null;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 1000, maxDelay: 30000 });
      errorHandler = getResponseErrorHandler();

      const mockRequest = vi.fn().mockImplementation(async (config) => {
        callCount++;
        if (callCount < 2) {
          const retryError = createMockAxiosError(503);
          retryError.config = config;
          return errorHandler!(retryError);
        }
        return { data: 'success', status: 200 };
      });
      instance.request = mockRequest;

      const error = createMockAxiosError(503);
      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();

      await retryPromise;
      // First retry fails, second retry succeeds
      expect(callCount).toBe(2);
    });

    it('should respect maxDelay for exponential backoff', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      let callCount = 0;
      let errorHandler: ((error: AxiosError) => Promise<AxiosResponse>) | null = null;

      // With baseDelay 5000 and maxDelay 10000, delays should cap at 10000
      addRetryInterceptor(instance, { maxRetries: 5, baseDelay: 5000, maxDelay: 10000 });
      errorHandler = getResponseErrorHandler();

      const mockRequest = vi.fn().mockImplementation(async (config) => {
        callCount++;
        if (callCount < 3) {
          const retryError = createMockAxiosError(503);
          retryError.config = config;
          return errorHandler!(retryError);
        }
        return { data: 'success', status: 200 };
      });
      instance.request = mockRequest;

      const error = createMockAxiosError(503);
      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();

      await retryPromise;
      expect(callCount).toBe(3);
    });
  });

  describe('logging', () => {
    it('should log retry attempts when logging is enabled', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      const mockLogger: RetryLogger = {
        log: vi.fn(),
      };

      addRetryInterceptor(instance, {
        maxRetries: 3,
        baseDelay: 100,
        enableLogging: true,
        logger: mockLogger,
      });

      const error = createMockAxiosError(503);
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();
      await retryPromise;

      expect(mockLogger.log).toHaveBeenCalled();
      const logMessage = (mockLogger.log as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(logMessage).toContain('[Capsara SDK]');
      expect(logMessage).toContain('Retry attempt');
    });

    it('should log with server-suggested delay message', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      const mockLogger: RetryLogger = {
        log: vi.fn(),
      };

      addRetryInterceptor(instance, {
        maxRetries: 3,
        baseDelay: 100,
        enableLogging: true,
        logger: mockLogger,
      });

      const error = createMockAxiosError(429, {}, { 'retry-after': '5' });
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();
      await retryPromise;

      const logMessage = (mockLogger.log as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(logMessage).toContain('server suggested');
    });

    it('should log with exponential backoff message when no server delay', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      const mockLogger: RetryLogger = {
        log: vi.fn(),
      };

      addRetryInterceptor(instance, {
        maxRetries: 3,
        baseDelay: 100,
        enableLogging: true,
        logger: mockLogger,
      });

      const error = createMockAxiosError(503);
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();
      await retryPromise;

      const logMessage = (mockLogger.log as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(logMessage).toContain('exponential backoff');
    });

    it('should not log when logging is disabled', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      const mockLogger: RetryLogger = {
        log: vi.fn(),
      };

      addRetryInterceptor(instance, {
        maxRetries: 3,
        baseDelay: 100,
        enableLogging: false,
        logger: mockLogger,
      });

      const error = createMockAxiosError(503);
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();
      await retryPromise;

      expect(mockLogger.log).not.toHaveBeenCalled();
    });

    it('should use default console logger when not provided', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      addRetryInterceptor(instance, {
        maxRetries: 3,
        baseDelay: 100,
        enableLogging: true,
        // No custom logger - should use default
      });

      const error = createMockAxiosError(503);
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();
      await retryPromise;

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });

  describe('default configuration', () => {
    it('should use default maxRetries of 3', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      let callCount = 0;
      let errorHandler: ((error: AxiosError) => Promise<AxiosResponse>) | null = null;

      // No config - should use defaults
      addRetryInterceptor(instance);
      errorHandler = getResponseErrorHandler();

      const mockRequest = vi.fn().mockImplementation(async (config) => {
        callCount++;
        const retryError = createMockAxiosError(503);
        retryError.config = config;
        // Simulate axios calling interceptor on error
        return errorHandler!(retryError);
      });
      instance.request = mockRequest;

      const error = createMockAxiosError(503);
      const retryPromise = errorHandler!(error);
      const rejection = expect(retryPromise).rejects.toThrow();
      await vi.runAllTimersAsync();

      await rejection;
      expect(callCount).toBe(3); // 3 retries
    });

    it('should use default baseDelay of 1000ms', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance);

      const error = createMockAxiosError(503);
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);

      // Should not have retried yet at 500ms
      await vi.advanceTimersByTimeAsync(500);
      expect(mockRequest).not.toHaveBeenCalled();

      // Should have retried by 1500ms (accounting for jitter)
      await vi.advanceTimersByTimeAsync(1000);
      await retryPromise;
      expect(mockRequest).toHaveBeenCalled();
    });
  });

  describe('RetryConfig interface', () => {
    it('should accept partial config', () => {
      const { instance } = createMockAxiosInstance();

      // Should accept any subset of config options
      addRetryInterceptor(instance, { maxRetries: 5 });
      addRetryInterceptor(instance, { baseDelay: 500 });
      addRetryInterceptor(instance, { maxDelay: 60000 });
      addRetryInterceptor(instance, { enableLogging: true });
      addRetryInterceptor(instance, { logger: { log: vi.fn() } });

      expect(instance.interceptors.response.use).toHaveBeenCalledTimes(5);
    });

    it('should accept empty config', () => {
      const { instance } = createMockAxiosInstance();

      addRetryInterceptor(instance, {});

      expect(instance.interceptors.response.use).toHaveBeenCalled();
    });
  });

  describe('network drops and timeouts', () => {
    function networkError(method: string, code?: string, message = 'socket hang up'): AxiosError {
      const error = createMockNetworkError({ url: '/test', method, headers: {} } as Partial<InternalAxiosRequestConfig>);
      error.message = message;
      if (code) error.code = code;
      return error;
    }

    it('should retry a dropped connection on GET', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 200 });
      instance.request = mockRequest;
      addRetryInterceptor(instance, { baseDelay: 100 });

      const retryPromise = getResponseErrorHandler()!(networkError('get', 'ECONNRESET'));
      await vi.runAllTimersAsync();

      await expect(retryPromise).resolves.toMatchObject({ status: 200 });
      expect(mockRequest).toHaveBeenCalledOnce();
    });

    it('should retry a dropped connection on POST', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 201 });
      instance.request = mockRequest;
      addRetryInterceptor(instance, { baseDelay: 100 });

      const retryPromise = getResponseErrorHandler()!(networkError('post', 'ECONNREFUSED'));
      await vi.runAllTimersAsync();

      await expect(retryPromise).resolves.toMatchObject({ status: 201 });
      expect(mockRequest).toHaveBeenCalledOnce();
    });

    it('should retry a timeout on GET', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 200 });
      instance.request = mockRequest;
      addRetryInterceptor(instance, { baseDelay: 100 });

      const retryPromise = getResponseErrorHandler()!(networkError('get', 'ECONNABORTED', 'timeout of 100ms exceeded'));
      await vi.runAllTimersAsync();

      await expect(retryPromise).resolves.toMatchObject({ status: 200 });
    });

    it('should not retry a timeout on POST', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn();
      instance.request = mockRequest;
      addRetryInterceptor(instance, { baseDelay: 100 });

      const error = networkError('post', 'ECONNABORTED', 'timeout of 100ms exceeded');
      await expect(getResponseErrorHandler()!(error)).rejects.toBe(error);
      expect(mockRequest).not.toHaveBeenCalled();
    });

    it('should not retry a POST that timed out with ETIMEDOUT', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn();
      instance.request = mockRequest;
      addRetryInterceptor(instance, { baseDelay: 100 });

      await expect(getResponseErrorHandler()!(networkError('post', 'ETIMEDOUT', 'connect ETIMEDOUT'))).rejects.toBeDefined();
      expect(mockRequest).not.toHaveBeenCalled();
    });

    it.each(['ECONNRESET', 'EPIPE', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ENETUNREACH', 'ENETDOWN', 'EHOSTUNREACH'])(
      'should retry %s on POST',
      async (code) => {
        const { instance, getResponseErrorHandler } = createMockAxiosInstance();
        const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 201 });
        instance.request = mockRequest;
        addRetryInterceptor(instance, { baseDelay: 100 });

        const retryPromise = getResponseErrorHandler()!(networkError('post', code));
        await vi.runAllTimersAsync();

        await expect(retryPromise).resolves.toMatchObject({ status: 201 });
      }
    );

    it.each([
      ['a TLS failure', 'CERT_HAS_EXPIRED'],
      ['an unknown network error', 'ERR_NETWORK'],
      ['an error without a code', undefined],
    ])('should not retry %s', async (_label, code) => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn();
      instance.request = mockRequest;
      addRetryInterceptor(instance, { baseDelay: 100 });

      const error = networkError('get', code);
      await expect(getResponseErrorHandler()!(error)).rejects.toBe(error);
      expect(mockRequest).not.toHaveBeenCalled();
    });

    it('should cap a server hint at 30 seconds even when maxDelay is higher', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 200 });
      instance.request = mockRequest;
      addRetryInterceptor(instance, { maxDelay: 120_000 });

      const retryPromise = getResponseErrorHandler()!(createMockAxiosError(429, { error: { retryAfter: 90 } }));
      await vi.advanceTimersByTimeAsync(29_999);
      expect(mockRequest).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      await retryPromise;
      expect(mockRequest).toHaveBeenCalledOnce();
    });

    it('should accept a fractional Retry-After header', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'ok', status: 200 });
      instance.request = mockRequest;
      addRetryInterceptor(instance, { baseDelay: 10_000 });

      const retryPromise = getResponseErrorHandler()!(createMockAxiosError(503, {}, { 'retry-after': '1.5' }));
      await vi.advanceTimersByTimeAsync(1_499);
      expect(mockRequest).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      await retryPromise;
      expect(mockRequest).toHaveBeenCalledOnce();
    });

    it('should give up on dropped connections after maxRetries', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      addRetryInterceptor(instance, { baseDelay: 100 });
      const handler = getResponseErrorHandler()!;
      let calls = 0;
      instance.request = vi.fn().mockImplementation((config: InternalAxiosRequestConfig) => {
        calls++;
        const again = networkError('post', 'ECONNRESET');
        again.config = config;
        return handler(again);
      });

      const promise = handler(networkError('post', 'ECONNRESET'));
      const rejection = expect(promise).rejects.toMatchObject({ code: 'ECONNRESET' });
      await vi.runAllTimersAsync();
      await rejection;
      expect(calls).toBe(3);
    });
  });

  describe('edge cases', () => {
    it('should back off on 429 with an unparseable Retry-After header', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100 });

      const retryPromise = getResponseErrorHandler()!(createMockAxiosError(429, {}, { 'retry-after': 'invalid-date' }));
      await vi.runAllTimersAsync();

      await retryPromise;
      expect(mockRequest).toHaveBeenCalledOnce();
    });

    it('should handle past date in Retry-After header', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100 });

      // Date in the past
      const pastDate = new Date('2024-01-01T11:00:00Z');
      const error = createMockAxiosError(429, {}, { 'retry-after': pastDate.toUTCString() });
      const errorHandler = getResponseErrorHandler();

      const retryPromise = errorHandler!(error);
      await vi.runAllTimersAsync();

      // Should use 0 delay (immediate retry)
      await retryPromise;
      expect(mockRequest).toHaveBeenCalled();
    });

    it.each([
      ['a non-number body retryAfter', { error: { retryAfter: 'five', message: 'Rate limited' } }],
      ['null response data', null],
      ['a body without an error field', { message: 'Rate limited' }],
      ['a null error field', { error: null }],
      ['a non-JSON text body', 'Too Many Requests'],
    ])('should back off on 429 with %s', async (_label, data) => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 1000 });

      const retryPromise = getResponseErrorHandler()!(createMockAxiosError(429, data));
      await vi.advanceTimersByTimeAsync(999);
      expect(mockRequest).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(301);
      await retryPromise;
      expect(mockRequest).toHaveBeenCalledOnce();
    });

    it('should read retryAfter from a JSON text body', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      const mockRequest = vi.fn().mockResolvedValue({ data: 'success', status: 200 });
      instance.request = mockRequest;

      addRetryInterceptor(instance, { maxRetries: 3, baseDelay: 100 });

      const retryPromise = getResponseErrorHandler()!(createMockAxiosError(503, '{"error":{"retryAfter":4}}'));
      await vi.advanceTimersByTimeAsync(3999);
      expect(mockRequest).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      await retryPromise;
      expect(mockRequest).toHaveBeenCalledOnce();
    });

    it('should wrap a non-Error rejection without config', async () => {
      const { instance, getResponseErrorHandler } = createMockAxiosInstance();
      addRetryInterceptor(instance);

      await expect(getResponseErrorHandler()!('boom' as unknown as AxiosError)).rejects.toThrow('boom');
    });
  });
});
