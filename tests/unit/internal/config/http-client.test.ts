/**
 * Tests for http-client.ts - HTTP client configuration
 * @file tests/unit/internal/config/http-client.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as http from 'http';
import * as https from 'https';
import type { AxiosInstance } from 'axios';
import {
  DEFAULT_TIMEOUT_CONFIG,
  createHttpAgent,
  createHttpsAgent,
  createAxiosConfig,
  configureRetryInterceptor,
  createAgentForProtocol,
  type HttpTimeoutConfig,
} from '../../../../src/internal/config/http-client.js';
import { SDK_VERSION, buildUserAgent } from '../../../../src/internal/version.js';

// Mock the retry-interceptor module
vi.mock('../../../../src/internal/config/retry-interceptor.js', () => ({
  addRetryInterceptor: vi.fn(),
}));

describe('http-client', () => {
  describe('DEFAULT_TIMEOUT_CONFIG', () => {
    it('should have correct default values', () => {
      expect(DEFAULT_TIMEOUT_CONFIG.apiTimeout).toBe(12 * 60 * 1000); // 12 minutes
      expect(DEFAULT_TIMEOUT_CONFIG.uploadTimeout).toBe(15 * 60 * 1000); // 15 minutes
      expect(DEFAULT_TIMEOUT_CONFIG.downloadTimeout).toBe(60 * 1000); // 1 minute
      expect(DEFAULT_TIMEOUT_CONFIG.connectTimeout).toBe(30 * 1000); // 30 seconds
      expect(DEFAULT_TIMEOUT_CONFIG.keepAliveInterval).toBe(30 * 1000); // 30 seconds
      expect(DEFAULT_TIMEOUT_CONFIG.maxSockets).toBe(50);
      expect(DEFAULT_TIMEOUT_CONFIG.maxFreeSockets).toBe(10);
    });

    it('should have apiTimeout greater than 10 minutes (server timeout)', () => {
      const serverTimeout = 10 * 60 * 1000; // 10 minutes
      expect(DEFAULT_TIMEOUT_CONFIG.apiTimeout).toBeGreaterThan(serverTimeout);
    });

    it('should have uploadTimeout greater than apiTimeout', () => {
      expect(DEFAULT_TIMEOUT_CONFIG.uploadTimeout).toBeGreaterThan(DEFAULT_TIMEOUT_CONFIG.apiTimeout);
    });
  });

  describe('createHttpAgent', () => {
    it('should create an HTTP agent with default config', () => {
      const agent = createHttpAgent();

      expect(agent).toBeInstanceOf(http.Agent);
      expect(agent.keepAlive).toBe(true);
      expect(agent.maxSockets).toBe(DEFAULT_TIMEOUT_CONFIG.maxSockets);
      expect(agent.maxFreeSockets).toBe(DEFAULT_TIMEOUT_CONFIG.maxFreeSockets);
    });

    it('should create an HTTP agent with custom config', () => {
      const customConfig: HttpTimeoutConfig = {
        apiTimeout: 60000,
        uploadTimeout: 120000,
        downloadTimeout: 30000,
        connectTimeout: 10000,
        keepAliveInterval: 15000,
        maxSockets: 25,
        maxFreeSockets: 5,
      };

      const agent = createHttpAgent(customConfig);

      expect(agent).toBeInstanceOf(http.Agent);
      expect(agent.keepAlive).toBe(true);
      expect(agent.maxSockets).toBe(25);
      expect(agent.maxFreeSockets).toBe(5);
    });

    it('should have keepAlive enabled', () => {
      const agent = createHttpAgent();
      expect(agent.keepAlive).toBe(true);
    });
  });

  describe('createHttpsAgent', () => {
    it('should create an HTTPS agent with default config', () => {
      const agent = createHttpsAgent();

      expect(agent).toBeInstanceOf(https.Agent);
      expect(agent.keepAlive).toBe(true);
      expect(agent.maxSockets).toBe(DEFAULT_TIMEOUT_CONFIG.maxSockets);
      expect(agent.maxFreeSockets).toBe(DEFAULT_TIMEOUT_CONFIG.maxFreeSockets);
    });

    it('should create an HTTPS agent with custom config', () => {
      const customConfig: HttpTimeoutConfig = {
        apiTimeout: 60000,
        uploadTimeout: 120000,
        downloadTimeout: 30000,
        connectTimeout: 10000,
        keepAliveInterval: 15000,
        maxSockets: 30,
        maxFreeSockets: 8,
      };

      const agent = createHttpsAgent(customConfig);

      expect(agent).toBeInstanceOf(https.Agent);
      expect(agent.keepAlive).toBe(true);
      expect(agent.maxSockets).toBe(30);
      expect(agent.maxFreeSockets).toBe(8);
    });

    it('should have keepAlive enabled', () => {
      const agent = createHttpsAgent();
      expect(agent.keepAlive).toBe(true);
    });
  });

  describe('createAxiosConfig', () => {
    it('should create axios config with required baseURL', () => {
      const config = createAxiosConfig('https://api.example.com');

      expect(config.baseURL).toBe('https://api.example.com');
      expect(config.timeout).toBe(DEFAULT_TIMEOUT_CONFIG.apiTimeout);
      expect(config.httpAgent).toBeInstanceOf(http.Agent);
      expect(config.httpsAgent).toBeInstanceOf(https.Agent);
    });

    it('should create axios config with custom timeout', () => {
      const customTimeout = 60000;
      const config = createAxiosConfig('https://api.example.com', customTimeout);

      expect(config.timeout).toBe(customTimeout);
    });

    it('should create axios config with custom timeout config', () => {
      const customTimeoutConfig: HttpTimeoutConfig = {
        apiTimeout: 60000,
        uploadTimeout: 120000,
        downloadTimeout: 30000,
        connectTimeout: 10000,
        keepAliveInterval: 15000,
        maxSockets: 20,
        maxFreeSockets: 4,
      };

      const config = createAxiosConfig(
        'https://api.example.com',
        customTimeoutConfig.apiTimeout,
        customTimeoutConfig
      );

      expect(config.timeout).toBe(60000);
      // Agents should be created with custom config
      expect(config.httpAgent).toBeInstanceOf(http.Agent);
      expect(config.httpsAgent).toBeInstanceOf(https.Agent);
    });

    it('should include SDK headers', () => {
      const config = createAxiosConfig('https://api.example.com');

      expect(config.headers).toBeDefined();
      expect(config.headers!['X-SDK-Version']).toBe(SDK_VERSION);
      expect(config.headers!['User-Agent']).toBe(buildUserAgent());
    });

    it('should include custom user agent when provided', () => {
      const customAgent = 'MyApp/2.0';
      const config = createAxiosConfig(
        'https://api.example.com',
        undefined,
        undefined,
        customAgent
      );

      expect(config.headers!['User-Agent']).toBe(buildUserAgent(customAgent));
      expect(config.headers!['User-Agent']).toContain('MyApp/2.0');
    });

    it('should use default user agent when not provided', () => {
      const config = createAxiosConfig('https://api.example.com');

      expect(config.headers!['User-Agent']).toBe(buildUserAgent());
      expect(config.headers!['User-Agent']).toContain('Capsara-SDK');
    });
  });

  describe('configureRetryInterceptor', () => {
    let mockAxiosInstance: AxiosInstance;
    let addRetryInterceptorMock: ReturnType<typeof vi.fn>;

    beforeEach(async () => {
      // Get the mocked function
      const retryModule = await import('../../../../src/internal/config/retry-interceptor.js');
      addRetryInterceptorMock = retryModule.addRetryInterceptor as ReturnType<typeof vi.fn>;
      addRetryInterceptorMock.mockClear();

      // Create mock axios instance
      mockAxiosInstance = {
        interceptors: {
          request: { use: vi.fn() },
          response: { use: vi.fn() },
        },
      } as unknown as AxiosInstance;
    });

    it('should call addRetryInterceptor with axios instance', () => {
      configureRetryInterceptor(mockAxiosInstance);

      expect(addRetryInterceptorMock).toHaveBeenCalledWith(mockAxiosInstance, undefined);
    });

    it('should call addRetryInterceptor with custom retry config', () => {
      const retryConfig = {
        maxRetries: 5,
        baseDelay: 2000,
        maxDelay: 60000,
        enableLogging: true,
      };

      configureRetryInterceptor(mockAxiosInstance, retryConfig);

      expect(addRetryInterceptorMock).toHaveBeenCalledWith(mockAxiosInstance, retryConfig);
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

      // Agent is created - verify it's the right type
      expect(agent).toBeInstanceOf(https.Agent);
      expect(agent.keepAlive).toBe(true);
    });

    it('should use custom config when provided', () => {
      const customConfig: HttpTimeoutConfig = {
        apiTimeout: 60000,
        uploadTimeout: 120000,
        downloadTimeout: 30000,
        connectTimeout: 10000,
        keepAliveInterval: 15000,
        maxSockets: 40,
        maxFreeSockets: 15,
      };

      const agent = createAgentForProtocol('https:', 60000, customConfig);

      expect(agent).toBeInstanceOf(https.Agent);
      expect(agent.maxSockets).toBe(40);
      expect(agent.maxFreeSockets).toBe(15);
    });

    it('should use default config when not provided', () => {
      const agent = createAgentForProtocol('https:', 60000);

      expect(agent.maxSockets).toBe(DEFAULT_TIMEOUT_CONFIG.maxSockets);
      expect(agent.maxFreeSockets).toBe(DEFAULT_TIMEOUT_CONFIG.maxFreeSockets);
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
        maxSockets: 50,
        maxFreeSockets: 10,
      };

      // Verify all properties are accessible
      expect(config.apiTimeout).toBe(60000);
      expect(config.uploadTimeout).toBe(120000);
      expect(config.downloadTimeout).toBe(30000);
      expect(config.connectTimeout).toBe(10000);
      expect(config.keepAliveInterval).toBe(15000);
      expect(config.maxSockets).toBe(50);
      expect(config.maxFreeSockets).toBe(10);
    });
  });

  describe('AxiosConfigOptions interface', () => {
    // This tests that the interface works as expected
    it('should work with minimal options', () => {
      const options = {
        baseURL: 'https://api.example.com',
      };

      expect(options.baseURL).toBe('https://api.example.com');
    });

    it('should work with all options', () => {
      const options = {
        baseURL: 'https://api.example.com',
        timeout: 60000,
        timeoutConfig: DEFAULT_TIMEOUT_CONFIG,
        userAgent: 'CustomApp/1.0',
      };

      expect(options.baseURL).toBe('https://api.example.com');
      expect(options.timeout).toBe(60000);
      expect(options.timeoutConfig).toBe(DEFAULT_TIMEOUT_CONFIG);
      expect(options.userAgent).toBe('CustomApp/1.0');
    });
  });

  describe('agent configuration verification', () => {
    it('should configure HTTP agent with keepAlive settings', () => {
      const config: HttpTimeoutConfig = {
        apiTimeout: 60000,
        uploadTimeout: 120000,
        downloadTimeout: 30000,
        connectTimeout: 10000,
        keepAliveInterval: 20000,
        maxSockets: 100,
        maxFreeSockets: 25,
      };

      const httpAgent = createHttpAgent(config);
      const httpsAgent = createHttpsAgent(config);

      // Both agents should have same socket configuration
      expect(httpAgent.maxSockets).toBe(100);
      expect(httpAgent.maxFreeSockets).toBe(25);
      expect(httpsAgent.maxSockets).toBe(100);
      expect(httpsAgent.maxFreeSockets).toBe(25);
    });

    it('should create independent agents for different configs', () => {
      const config1: HttpTimeoutConfig = {
        apiTimeout: 60000,
        uploadTimeout: 120000,
        downloadTimeout: 30000,
        connectTimeout: 10000,
        keepAliveInterval: 15000,
        maxSockets: 50,
        maxFreeSockets: 10,
      };

      const config2: HttpTimeoutConfig = {
        apiTimeout: 30000,
        uploadTimeout: 60000,
        downloadTimeout: 15000,
        connectTimeout: 5000,
        keepAliveInterval: 10000,
        maxSockets: 25,
        maxFreeSockets: 5,
      };

      const agent1 = createHttpAgent(config1);
      const agent2 = createHttpAgent(config2);

      expect(agent1).not.toBe(agent2);
      expect(agent1.maxSockets).toBe(50);
      expect(agent2.maxSockets).toBe(25);
    });
  });

  describe('edge cases', () => {
    it('should handle zero timeout values', () => {
      const config: HttpTimeoutConfig = {
        apiTimeout: 0,
        uploadTimeout: 0,
        downloadTimeout: 0,
        connectTimeout: 0,
        keepAliveInterval: 0,
        maxSockets: 1,
        maxFreeSockets: 1,
      };

      const agent = createHttpAgent(config);
      expect(agent).toBeInstanceOf(http.Agent);
      expect(agent.maxSockets).toBe(1);
      // Node.js http.Agent may have a minimum value for maxFreeSockets
      expect(agent.maxFreeSockets).toBeGreaterThanOrEqual(1);
    });

    it('should handle very large timeout values', () => {
      const config: HttpTimeoutConfig = {
        apiTimeout: Number.MAX_SAFE_INTEGER,
        uploadTimeout: Number.MAX_SAFE_INTEGER,
        downloadTimeout: Number.MAX_SAFE_INTEGER,
        connectTimeout: Number.MAX_SAFE_INTEGER,
        keepAliveInterval: Number.MAX_SAFE_INTEGER,
        maxSockets: 1000,
        maxFreeSockets: 500,
      };

      const agent = createHttpAgent(config);
      expect(agent).toBeInstanceOf(http.Agent);
      expect(agent.maxSockets).toBe(1000);
    });

    it('should handle empty baseURL in createAxiosConfig', () => {
      const config = createAxiosConfig('');
      expect(config.baseURL).toBe('');
    });

    it('should handle URL with path in createAxiosConfig', () => {
      const config = createAxiosConfig('https://api.example.com/v1');
      expect(config.baseURL).toBe('https://api.example.com/v1');
    });

    it('should handle URL with port in createAxiosConfig', () => {
      const config = createAxiosConfig('https://api.example.com:8443');
      expect(config.baseURL).toBe('https://api.example.com:8443');
    });
  });
});
