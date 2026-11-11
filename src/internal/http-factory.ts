/**
 * HTTP client factory - eliminates HTTP setup duplication across services
 * @file capsara.sdk/typescript/src/internal/http-factory.ts
 */

import axios, { AxiosInstance } from 'axios';
import { createHttpAgent, createHttpsAgent } from './config/http-client.js';
import { addRetryInterceptor, type RetryConfig } from './config/retry-interceptor.js';
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
 * API server timeouts:
 * - Server request timeout: 10 minutes
 * - Server keepAlive: 11 minutes
 */
export const DEFAULT_TIMEOUT_CONFIG: HttpTimeoutConfig = {
  apiTimeout: 12 * 60 * 1000,        // 12 minutes (exceeds server 10 min timeout)
  uploadTimeout: 15 * 60 * 1000,     // 15 minutes for multipart uploads
  downloadTimeout: 60 * 1000,        // 1 minute for file downloads
  connectTimeout: 30 * 1000,         // 30 seconds for socket connection
  keepAliveInterval: 30 * 1000,      // 30 seconds keep-alive probe interval
  maxSockets: 10,                    // Max 10 concurrent sockets per host
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

export type { RetryLogger } from './config/retry-interceptor.js';

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
