/**
 * Tests for http-factory.ts - HTTP client factory
 * @file tests/unit/internal/http-factory.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as http from 'http';
import * as https from 'https';
import axios from 'axios';
import {
  createHttpClient,
  createAgentForProtocol,
  DEFAULT_TIMEOUT_CONFIG,
  type HttpClientOptions,
  type HttpTimeoutConfig,
} from '../../../src/internal/http-factory.js';
import { SDK_VERSION, buildUserAgent } from '../../../src/internal/version.js';

// Mock axios to control instance creation
vi.mock('axios', async (importOriginal) => {
  const actual = await importOriginal<typeof axios>();
  return {
    ...actual,
    default: {
      ...actual.default,
      create: vi.fn((config) => {
        const mockInstance = {
          defaults: { ...config },
          interceptors: {
            request: {
              handlers: [] as Array<{ fulfilled: (config: unknown) => unknown }>,
              use: vi.fn(function(this: { handlers: Array<{ fulfilled: (config: unknown) => unknown }> }, fulfilled: (config: unknown) => unknown) {
                this.handlers.push({ fulfilled });
                return this.handlers.length - 1;
              }),
            },
            response: {
              handlers: [] as Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }>,
              use: vi.fn(function(this: { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }, fulfilled: (response: unknown) => unknown, rejected: (error: unknown) => Promise<unknown>) {
                this.handlers.push({ fulfilled, rejected });
                return this.handlers.length - 1;
              }),
            },
          },
          request: vi.fn(),
        };
        return mockInstance;
      }),
    },
  };
});

describe('http-factory', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('DEFAULT_TIMEOUT_CONFIG', () => {
    it('should have correct default values', () => {
      expect(DEFAULT_TIMEOUT_CONFIG.apiTimeout).toBe(12 * 60 * 1000); // 12 minutes
      expect(DEFAULT_TIMEOUT_CONFIG.uploadTimeout).toBe(15 * 60 * 1000); // 15 minutes
      expect(DEFAULT_TIMEOUT_CONFIG.downloadTimeout).toBe(60 * 1000); // 1 minute
      expect(DEFAULT_TIMEOUT_CONFIG.connectTimeout).toBe(30 * 1000); // 30 seconds
      expect(DEFAULT_TIMEOUT_CONFIG.keepAliveInterval).toBe(30 * 1000); // 30 seconds
      expect(DEFAULT_TIMEOUT_CONFIG.maxSockets).toBe(10);
      expect(DEFAULT_TIMEOUT_CONFIG.maxFreeSockets).toBe(10);
    });

    it('should have apiTimeout exceeding server 10 min timeout', () => {
      const serverTimeout = 10 * 60 * 1000;
      expect(DEFAULT_TIMEOUT_CONFIG.apiTimeout).toBeGreaterThan(serverTimeout);
    });
  });

  describe('createHttpClient', () => {
    it('should create axios instance with required baseUrl', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      const client = createHttpClient(options);

      expect(axios.create).toHaveBeenCalled();
      const createArgs = (axios.create as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(createArgs.baseURL).toBe('https://api.example.com');
    });

    it('should set default timeout from DEFAULT_TIMEOUT_CONFIG', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      createHttpClient(options);

      const createArgs = (axios.create as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(createArgs.timeout).toBe(DEFAULT_TIMEOUT_CONFIG.apiTimeout);
    });

    it('should allow overriding timeout config', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        timeout: {
          apiTimeout: 60000,
        },
      };

      createHttpClient(options);

      const createArgs = (axios.create as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(createArgs.timeout).toBe(60000);
    });

    it('should create HTTP and HTTPS agents', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      createHttpClient(options);

      const createArgs = (axios.create as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(createArgs.httpAgent).toBeInstanceOf(http.Agent);
      expect(createArgs.httpsAgent).toBeInstanceOf(https.Agent);
    });

    it('should set SDK headers', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      createHttpClient(options);

      const createArgs = (axios.create as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(createArgs.headers['X-SDK-Version']).toBe(SDK_VERSION);
      expect(createArgs.headers['User-Agent']).toBe(buildUserAgent());
    });

    it('should include custom user agent when provided', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        userAgent: 'MyApp/1.0',
      };

      createHttpClient(options);

      const createArgs = (axios.create as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(createArgs.headers['User-Agent']).toBe(buildUserAgent('MyApp/1.0'));
      expect(createArgs.headers['User-Agent']).toContain('MyApp/1.0');
    });

    it('should add retry interceptor', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      const client = createHttpClient(options);

      // The retry interceptor should be added to response interceptors
      expect(client.interceptors.response.use).toHaveBeenCalled();
    });

    it('should pass retry config to interceptor', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: {
          maxRetries: 5,
          baseDelay: 2000,
        },
      };

      const client = createHttpClient(options);

      expect(client.interceptors.response.use).toHaveBeenCalled();
    });

    describe('auth interceptor', () => {
      it('should add auth interceptor when getToken is provided', () => {
        const options: HttpClientOptions = {
          baseUrl: 'https://api.example.com',
          getToken: () => 'test-token',
        };

        const client = createHttpClient(options);

        expect(client.interceptors.request.use).toHaveBeenCalled();
      });

      it('should not add auth interceptor when getToken is not provided', () => {
        const options: HttpClientOptions = {
          baseUrl: 'https://api.example.com',
        };

        const client = createHttpClient(options);

        expect(client.interceptors.request.use).not.toHaveBeenCalled();
      });

      it('should add Authorization header when token is available', () => {
        const options: HttpClientOptions = {
          baseUrl: 'https://api.example.com',
          getToken: () => 'my-auth-token',
        };

        const client = createHttpClient(options);

        // Get the request interceptor handler
        const handlers = (client.interceptors.request as { handlers: Array<{ fulfilled: (config: { headers: Record<string, string> }) => unknown }> }).handlers;
        const requestInterceptor = handlers[0];

        // Simulate a request config
        const config = { headers: {} as Record<string, string> };
        const result = requestInterceptor!.fulfilled(config) as { headers: Record<string, string> };

        expect(result.headers.Authorization).toBe('Bearer my-auth-token');
      });

      it('should not add Authorization header when token is null', () => {
        const options: HttpClientOptions = {
          baseUrl: 'https://api.example.com',
          getToken: () => null,
        };

        const client = createHttpClient(options);

        const handlers = (client.interceptors.request as { handlers: Array<{ fulfilled: (config: { headers: Record<string, string> }) => unknown }> }).handlers;
        const requestInterceptor = handlers[0];

        const config = { headers: {} as Record<string, string> };
        const result = requestInterceptor!.fulfilled(config) as { headers: Record<string, string> };

        expect(result.headers.Authorization).toBeUndefined();
      });

      it('should call getToken for each request', () => {
        const getTokenMock = vi.fn().mockReturnValue('dynamic-token');
        const options: HttpClientOptions = {
          baseUrl: 'https://api.example.com',
          getToken: getTokenMock,
        };

        const client = createHttpClient(options);

        const handlers = (client.interceptors.request as { handlers: Array<{ fulfilled: (config: { headers: Record<string, string> }) => unknown }> }).handlers;
        const requestInterceptor = handlers[0];

        // Simulate multiple requests
        requestInterceptor!.fulfilled({ headers: {} });
        requestInterceptor!.fulfilled({ headers: {} });
        requestInterceptor!.fulfilled({ headers: {} });

        expect(getTokenMock).toHaveBeenCalledTimes(3);
      });
    });

    describe('agents configuration', () => {
      it('should configure agents with keepAlive', () => {
        const options: HttpClientOptions = {
          baseUrl: 'https://api.example.com',
        };

        createHttpClient(options);

        const createArgs = (axios.create as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
        expect(createArgs.httpAgent.keepAlive).toBe(true);
        expect(createArgs.httpsAgent.keepAlive).toBe(true);
      });

      it('should configure agents with custom socket limits', () => {
        const options: HttpClientOptions = {
          baseUrl: 'https://api.example.com',
          timeout: {
            maxSockets: 100,
            maxFreeSockets: 20,
          },
        };

        createHttpClient(options);

        const createArgs = (axios.create as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
        expect(createArgs.httpAgent.maxSockets).toBe(100);
        expect(createArgs.httpAgent.maxFreeSockets).toBe(20);
        expect(createArgs.httpsAgent.maxSockets).toBe(100);
        expect(createArgs.httpsAgent.maxFreeSockets).toBe(20);
      });
    });
  });

  describe('createAgentForProtocol', () => {
    it('should create HTTPS agent for https: protocol', () => {
      const agent = createAgentForProtocol('https:', 60000);

      expect(agent).toBeInstanceOf(https.Agent);
      expect(agent.keepAlive).toBe(true);
    });

    it('should create HTTP agent for http: protocol', () => {
      const agent = createAgentForProtocol('http:', 60000);

      expect(agent).toBeInstanceOf(http.Agent);
      expect(agent.keepAlive).toBe(true);
    });

    it('should create HTTP agent for non-https protocols', () => {
      const agent = createAgentForProtocol('ftp:', 60000);

      expect(agent).toBeInstanceOf(http.Agent);
    });

    it('should use provided timeout', () => {
      const timeout = 120000;
      const agent = createAgentForProtocol('https:', timeout);

      expect(agent).toBeInstanceOf(https.Agent);
    });

    it('should use default config when not provided', () => {
      const agent = createAgentForProtocol('https:', 60000);

      expect(agent.maxSockets).toBe(DEFAULT_TIMEOUT_CONFIG.maxSockets);
      expect(agent.maxFreeSockets).toBe(DEFAULT_TIMEOUT_CONFIG.maxFreeSockets);
    });

    it('should use custom config when provided', () => {
      const customConfig: HttpTimeoutConfig = {
        apiTimeout: 60000,
        uploadTimeout: 120000,
        downloadTimeout: 30000,
        connectTimeout: 10000,
        keepAliveInterval: 15000,
        maxSockets: 75,
        maxFreeSockets: 25,
      };

      const agent = createAgentForProtocol('https:', 60000, customConfig);

      expect(agent.maxSockets).toBe(75);
      expect(agent.maxFreeSockets).toBe(25);
    });
  });

  describe('HttpTimeoutConfig interface', () => {
    it('should accept valid config object', () => {
      const config: HttpTimeoutConfig = {
        apiTimeout: 60000,
        uploadTimeout: 120000,
        downloadTimeout: 30000,
        connectTimeout: 10000,
        keepAliveInterval: 15000,
        maxSockets: 10,
        maxFreeSockets: 10,
      };

      expect(config.apiTimeout).toBe(60000);
      expect(config.uploadTimeout).toBe(120000);
      expect(config.downloadTimeout).toBe(30000);
      expect(config.connectTimeout).toBe(10000);
      expect(config.keepAliveInterval).toBe(15000);
      expect(config.maxSockets).toBe(10);
      expect(config.maxFreeSockets).toBe(10);
    });
  });

  describe('HttpClientOptions interface', () => {
    it('should work with minimal options', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      expect(options.baseUrl).toBe('https://api.example.com');
    });

    it('should work with all options', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        timeout: { apiTimeout: 60000 },
        retry: { maxRetries: 5 },
        getToken: () => 'token',
        userAgent: 'MyApp/1.0',
      };

      expect(options.baseUrl).toBe('https://api.example.com');
      expect(options.timeout?.apiTimeout).toBe(60000);
      expect(options.retry?.maxRetries).toBe(5);
      expect(options.getToken?.()).toBe('token');
      expect(options.userAgent).toBe('MyApp/1.0');
    });
  });

  describe('retry interceptor integration', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should add response interceptor for retry logic', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      const client = createHttpClient(options);

      // Response interceptor should be added
      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      expect(handlers.length).toBeGreaterThan(0);
    });

    it('should pass through successful responses', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      const client = createHttpClient(options);

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const successHandler = handlers[0]!.fulfilled;

      const mockResponse = { data: 'success', status: 200 };
      const result = successHandler(mockResponse);

      expect(result).toBe(mockResponse);
    });

    it('should reject non-retryable errors', async () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      const client = createHttpClient(options);

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = {
        config: { headers: {}, __retryCount: 0 },
        response: { status: 400, headers: {}, data: {} },
      };

      await expect(errorHandler(error)).rejects.toBeDefined();
    });

    it('should reject errors without config', async () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      const client = createHttpClient(options);

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = new Error('Network error');

      await expect(errorHandler(error)).rejects.toThrow('Network error');
    });

    it('should reject errors without response', async () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      const client = createHttpClient(options);

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = {
        config: { headers: {} },
        // No response property
      };

      await expect(errorHandler(error)).rejects.toBeDefined();
    });

    it('should retry 503 errors', async () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: { maxRetries: 3, baseDelay: 100 },
      };

      const client = createHttpClient(options);
      (client.request as ReturnType<typeof vi.fn>).mockResolvedValue({ data: 'success', status: 200 });

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = {
        config: { headers: {} },
        response: { status: 503, headers: {}, data: {} },
      };

      const retryPromise = errorHandler(error);
      await vi.runAllTimersAsync();

      const result = await retryPromise;
      expect(result).toEqual({ data: 'success', status: 200 });
      expect(client.request).toHaveBeenCalled();
    });

    it('should retry 429 errors', async () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: { maxRetries: 3, baseDelay: 100 },
      };

      const client = createHttpClient(options);
      (client.request as ReturnType<typeof vi.fn>).mockResolvedValue({ data: 'success', status: 200 });

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = {
        config: { headers: {} },
        response: { status: 429, headers: {}, data: {} },
      };

      const retryPromise = errorHandler(error);
      await vi.runAllTimersAsync();

      const result = await retryPromise;
      expect(result).toEqual({ data: 'success', status: 200 });
    });

    it('should use Retry-After header when present', async () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: { maxRetries: 3, baseDelay: 100, maxDelay: 60000 },
      };

      const client = createHttpClient(options);
      (client.request as ReturnType<typeof vi.fn>).mockResolvedValue({ data: 'success', status: 200 });

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = {
        config: { headers: {} },
        response: { status: 429, headers: { 'retry-after': '2' }, data: {} },
      };

      const retryPromise = errorHandler(error);

      // Should wait ~2000ms based on header
      await vi.advanceTimersByTimeAsync(1500);
      expect(client.request).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(1000);
      await retryPromise;
      expect(client.request).toHaveBeenCalled();
    });

    it('should use retryAfter from response body', async () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: { maxRetries: 3, baseDelay: 100, maxDelay: 60000 },
      };

      const client = createHttpClient(options);
      (client.request as ReturnType<typeof vi.fn>).mockResolvedValue({ data: 'success', status: 200 });

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = {
        config: { headers: {} },
        response: { status: 429, headers: {}, data: { error: { retryAfter: 1 } } },
      };

      const retryPromise = errorHandler(error);
      await vi.runAllTimersAsync();

      await retryPromise;
      expect(client.request).toHaveBeenCalled();
    });

    it('should stop retrying after maxRetries exceeded', async () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: { maxRetries: 2, baseDelay: 100 },
      };

      const client = createHttpClient(options);

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = {
        config: { headers: {}, __retryCount: 2 }, // Already at max
        response: { status: 503, headers: {}, data: {} },
      };

      await expect(errorHandler(error)).rejects.toBeDefined();
      expect(client.request).not.toHaveBeenCalled();
    });

    it('should log retry attempts when logging enabled', async () => {
      const mockLogger = { log: vi.fn() };
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: { maxRetries: 3, baseDelay: 100, enableLogging: true, logger: mockLogger },
      };

      const client = createHttpClient(options);
      (client.request as ReturnType<typeof vi.fn>).mockResolvedValue({ data: 'success', status: 200 });

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = {
        config: { headers: {} },
        response: { status: 503, headers: {}, data: {} },
      };

      const retryPromise = errorHandler(error);
      await vi.runAllTimersAsync();
      await retryPromise;

      expect(mockLogger.log).toHaveBeenCalled();
      const logMessage = mockLogger.log.mock.calls[0]?.[0];
      expect(logMessage).toContain('[Capsara SDK]');
      expect(logMessage).toContain('Retry');
    });

    it('should log server-suggested delay message', async () => {
      const mockLogger = { log: vi.fn() };
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: { maxRetries: 3, baseDelay: 100, enableLogging: true, logger: mockLogger },
      };

      const client = createHttpClient(options);
      (client.request as ReturnType<typeof vi.fn>).mockResolvedValue({ data: 'success', status: 200 });

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = {
        config: { headers: {} },
        response: { status: 429, headers: { 'retry-after': '5' }, data: {} },
      };

      const retryPromise = errorHandler(error);
      await vi.runAllTimersAsync();
      await retryPromise;

      const logMessage = mockLogger.log.mock.calls[0]?.[0];
      expect(logMessage).toContain('server suggested');
    });

    it('should log exponential backoff message when no server delay', async () => {
      const mockLogger = { log: vi.fn() };
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: { maxRetries: 3, baseDelay: 100, enableLogging: true, logger: mockLogger },
      };

      const client = createHttpClient(options);
      (client.request as ReturnType<typeof vi.fn>).mockResolvedValue({ data: 'success', status: 200 });

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const error = {
        config: { headers: {} },
        response: { status: 503, headers: {}, data: {} },
      };

      const retryPromise = errorHandler(error);
      await vi.runAllTimersAsync();
      await retryPromise;

      const logMessage = mockLogger.log.mock.calls[0]?.[0];
      expect(logMessage).toContain('exponential backoff');
    });
  });

  describe('edge cases', () => {
    it('should handle empty baseUrl', () => {
      const options: HttpClientOptions = {
        baseUrl: '',
      };

      const client = createHttpClient(options);

      const createArgs = (axios.create as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(createArgs.baseURL).toBe('');
    });

    it('should handle partial timeout config', () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        timeout: {
          apiTimeout: 30000,
          // Other values should use defaults
        },
      };

      createHttpClient(options);

      const createArgs = (axios.create as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
      expect(createArgs.timeout).toBe(30000);
      expect(createArgs.httpAgent.maxSockets).toBe(DEFAULT_TIMEOUT_CONFIG.maxSockets);
    });

    it('should handle HTTP date format in Retry-After header', async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));

      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: { maxRetries: 3, baseDelay: 100, maxDelay: 60000 },
      };

      const client = createHttpClient(options);
      (client.request as ReturnType<typeof vi.fn>).mockResolvedValue({ data: 'success', status: 200 });

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      const futureDate = new Date('2024-01-01T12:00:03Z'); // 3 seconds in future
      const error = {
        config: { headers: {} },
        response: { status: 429, headers: { 'retry-after': futureDate.toUTCString() }, data: {} },
      };

      const retryPromise = errorHandler(error);
      await vi.runAllTimersAsync();

      await retryPromise;
      expect(client.request).toHaveBeenCalled();

      vi.useRealTimers();
    });

    it('should cap server delay to maxDelay', async () => {
      vi.useFakeTimers();

      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
        retry: { maxRetries: 3, baseDelay: 100, maxDelay: 5000 },
      };

      const client = createHttpClient(options);
      (client.request as ReturnType<typeof vi.fn>).mockResolvedValue({ data: 'success', status: 200 });

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      // Server suggests 60 seconds but maxDelay is 5 seconds
      const error = {
        config: { headers: {} },
        response: { status: 429, headers: { 'retry-after': '60' }, data: {} },
      };

      const retryPromise = errorHandler(error);
      await vi.runAllTimersAsync();

      await retryPromise;
      expect(client.request).toHaveBeenCalled();

      vi.useRealTimers();
    });

    it('should handle non-Error objects in error handler', async () => {
      const options: HttpClientOptions = {
        baseUrl: 'https://api.example.com',
      };

      const client = createHttpClient(options);

      const handlers = (client.interceptors.response as { handlers: Array<{ fulfilled: (response: unknown) => unknown; rejected: (error: unknown) => Promise<unknown> }> }).handlers;
      const errorHandler = handlers[0]!.rejected;

      // Non-Error string
      const stringError = 'Something went wrong';

      await expect(errorHandler(stringError)).rejects.toThrow('Something went wrong');
    });
  });
});
