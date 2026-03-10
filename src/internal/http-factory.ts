/**
 * HTTP client factory - eliminates HTTP setup duplication across services
 * @file capsara.sdk/typescript/src/internal/http-factory.ts
 */

import axios, { AxiosInstance } from 'axios';
import * as http from 'http';
import * as https from 'https';
import type { RetryConfig } from './config/retry-interceptor.js';
import { SDK_VERSION, buildUserAgent } from './version.js';

/**
 * HTTP client timeout configuration
 */
export interface HttpTimeoutConfig {
  /** Timeout for standard API requests (ms) */
  apiTimeout: number;
  /** Timeout for multipart envelope uploads (ms) */
  uploadTimeout: number;
  /** Timeout for file downloads (ms) */
  downloadTimeout: number;
  /** Socket connection timeout (ms) */
  connectTimeout: number;
  /** Keep-alive probe interval (ms) */
  keepAliveInterval: number;
  /** Maximum concurrent sockets per host */
  maxSockets: number;
  /** Maximum idle sockets to keep alive */
  maxFreeSockets: number;
}

/**
 * Default timeout configuration
 *
 * CRITICAL: SDK timeouts must EXCEED server timeouts to prevent ECONNRESET errors
 *
 * vault.api server timeouts:
 * - Server request timeout: 10 minutes
 * - Server keepAlive: 11 minutes
 * - MongoDB socket timeout: 30 seconds
 * - Circuit breaker timeout: 30 seconds
 */
export const DEFAULT_TIMEOUT_CONFIG: HttpTimeoutConfig = {
  apiTimeout: 12 * 60 * 1000,        // 12 minutes (exceeds server 10 min timeout)
  uploadTimeout: 15 * 60 * 1000,     // 15 minutes for multipart uploads
  downloadTimeout: 60 * 1000,        // 1 minute for file downloads
  connectTimeout: 30 * 1000,         // 30 seconds for socket connection
  keepAliveInterval: 30 * 1000,      // 30 seconds keep-alive probe interval
  maxSockets: 50,                    // Max 50 concurrent sockets per host
  maxFreeSockets: 10,                // Keep 10 idle sockets alive
};

/**
 * Options for creating an HTTP client
 */
export interface HttpClientOptions {
  /** API base URL */
  baseUrl: string;
  /** Timeout configuration */
  timeout?: Partial<HttpTimeoutConfig>;
  /** Retry configuration */
  retry?: RetryConfig;
  /** Function to get auth token (for authenticated requests) */
  getToken?: () => string | null;
  /** Custom user agent string to append to default SDK user agent */
  userAgent?: string;
}

/**
 * Create HTTP agent with keep-alive and timeout configuration
 */
function createHttpAgent(config: HttpTimeoutConfig): http.Agent {
  return new http.Agent({
    keepAlive: true,
    keepAliveMsecs: config.keepAliveInterval,
    timeout: config.apiTimeout,
    maxSockets: config.maxSockets,
    maxFreeSockets: config.maxFreeSockets,
  });
}

/**
 * Create HTTPS agent with keep-alive and timeout configuration
 */
function createHttpsAgent(config: HttpTimeoutConfig): https.Agent {
  return new https.Agent({
    keepAlive: true,
    keepAliveMsecs: config.keepAliveInterval,
    timeout: config.apiTimeout,
    maxSockets: config.maxSockets,
    maxFreeSockets: config.maxFreeSockets,
  });
}

/**
 * Logger interface for retry interceptor
 */
export interface RetryLogger {
  log: (message: string) => void;
}

/**
 * Default retry configuration
 */
const DEFAULT_RETRY_CONFIG: Required<RetryConfig> = {
  maxRetries: 3,
  baseDelay: 1000,
  maxDelay: 30000,
  enableLogging: false,
  // eslint-disable-next-line no-console
  logger: { log: (msg: string) => console.log(msg) },
};

/**
 * Calculate retry delay using exponential backoff
 */
function calculateExponentialBackoff(retryCount: number, baseDelay: number, maxDelay: number): number {
  const exponentialDelay = baseDelay * Math.pow(2, retryCount);
  const jitter = Math.random() * 0.3 * exponentialDelay;
  return Math.min(Math.floor(exponentialDelay + jitter), maxDelay);
}

/**
 * Sleep for specified duration
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => globalThis.setTimeout(resolve, ms));
}

/**
 * Check if error is retryable (503 or 429)
 */
function isRetryableStatus(status: number): boolean {
  return status === 503 || status === 429;
}

/**
 * Extract retry delay from server response
 */
function getServerSuggestedDelay(response: { headers?: Record<string, string>; data?: unknown }): number | null {
  // Check response body for retryAfter field
  const data = response.data as { error?: { retryAfter?: number } } | undefined;
  if (data?.error?.retryAfter && typeof data.error.retryAfter === 'number') {
    return data.error.retryAfter * 1000;
  }

  // Check Retry-After header
  const retryAfter = response.headers?.['retry-after'];
  if (retryAfter) {
    const seconds = parseInt(retryAfter, 10);
    if (!isNaN(seconds)) {
      return seconds * 1000;
    }
    const date = new Date(retryAfter);
    if (!isNaN(date.getTime())) {
      const delay = date.getTime() - Date.now();
      return delay > 0 ? delay : 0;
    }
  }

  return null;
}

/**
 * Add retry interceptor to axios instance
 */
function addRetryInterceptor(axiosInstance: AxiosInstance, config: RetryConfig = {}): void {
  const retryConfig = { ...DEFAULT_RETRY_CONFIG, ...config };

  interface AxiosConfigWithRetry {
    __retryCount?: number;
    headers: Record<string, string>;
    [key: string]: unknown;
  }

  axiosInstance.interceptors.response.use(
    (response) => response,
    async (error: unknown) => {
      // Type guard for axios error structure
      const axiosError = error as { config?: AxiosConfigWithRetry; response?: { status: number; headers: Record<string, string>; data: unknown } };
      const requestConfig = axiosError.config;
      if (!requestConfig) {
        return Promise.reject(error instanceof Error ? error : new Error(String(error)));
      }

      if (requestConfig.__retryCount === undefined) {
        requestConfig.__retryCount = 0;
      }

      const status = axiosError.response?.status;
      if (!status || !isRetryableStatus(status) || requestConfig.__retryCount >= retryConfig.maxRetries) {
        return Promise.reject(error instanceof Error ? error : new Error(String(error)));
      }

      requestConfig.__retryCount++;

      let retryDelay: number;
      const serverDelay = axiosError.response ? getServerSuggestedDelay(axiosError.response) : null;

      if (serverDelay !== null) {
        retryDelay = Math.min(serverDelay, retryConfig.maxDelay);
        if (retryConfig.enableLogging) {
          retryConfig.logger.log(
            `[Capsara SDK] Retry ${requestConfig.__retryCount}/${retryConfig.maxRetries} for ${status} - waiting ${retryDelay}ms (server suggested)`
          );
        }
      } else {
        retryDelay = calculateExponentialBackoff(requestConfig.__retryCount - 1, retryConfig.baseDelay, retryConfig.maxDelay);
        if (retryConfig.enableLogging) {
          retryConfig.logger.log(
            `[Capsara SDK] Retry ${requestConfig.__retryCount}/${retryConfig.maxRetries} for ${status} - waiting ${retryDelay}ms (exponential backoff)`
          );
        }
      }

      await sleep(retryDelay);
      return axiosInstance.request(requestConfig as Parameters<typeof axiosInstance.request>[0]);
    }
  );
}

/**
 * Create a configured axios instance with retry and optional auth
 *
 * This factory eliminates the HTTP setup duplication found in AuthClient,
 * KeyManager, LimitsManager, AccountClient, and CapsaraClient.
 *
 * @param options - HTTP client configuration
 * @returns Configured axios instance
 */
export function createHttpClient(options: HttpClientOptions): AxiosInstance {
  const timeoutConfig = { ...DEFAULT_TIMEOUT_CONFIG, ...options.timeout };

  const axiosConfig = {
    baseURL: options.baseUrl,
    timeout: timeoutConfig.apiTimeout,
    httpAgent: createHttpAgent(timeoutConfig),
    httpsAgent: createHttpsAgent(timeoutConfig),
    headers: {
      'User-Agent': buildUserAgent(options.userAgent),
      'X-SDK-Version': SDK_VERSION,
    },
  };

  const axiosInstance = axios.create(axiosConfig);

  // Add retry interceptor
  addRetryInterceptor(axiosInstance, options.retry);

  // Add auth interceptor if token getter provided
  if (options.getToken) {
    const getToken = options.getToken;
    axiosInstance.interceptors.request.use((config) => {
      const token = getToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
  }

  return axiosInstance;
}

/**
 * Create HTTP/HTTPS agent for raw requests with custom timeout
 * @param protocol - 'http:' or 'https:'
 * @param timeout - Request timeout in milliseconds
 * @param config - Timeout configuration
 */
export function createAgentForProtocol(
  protocol: string,
  timeout: number,
  config: HttpTimeoutConfig = DEFAULT_TIMEOUT_CONFIG
): http.Agent | https.Agent {
  const agentConfig = {
    keepAlive: true,
    keepAliveMsecs: config.keepAliveInterval,
    timeout,
    maxSockets: config.maxSockets,
    maxFreeSockets: config.maxFreeSockets,
  };

  return protocol === 'https:'
    ? new https.Agent(agentConfig)
    : new http.Agent(agentConfig);
}
