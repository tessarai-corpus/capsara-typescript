// HTTP client configuration with timeout and keep-alive settings.

import * as http from 'http';
import * as https from 'https';
import type { AxiosRequestConfig, AxiosInstance } from 'axios';
import { addRetryInterceptor, type RetryConfig } from './retry-interceptor.js';
import { SDK_VERSION, buildUserAgent } from '../version.js';

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

// SDK timeouts must exceed server timeouts to avoid ECONNRESET errors.
// If SDK timeout < server timeout, client kills the connection before the server responds.
// vault.api server timeout: 10 min request, 11 min keepAlive, 30s MongoDB/circuit breaker.
export const DEFAULT_TIMEOUT_CONFIG: HttpTimeoutConfig = {
  apiTimeout: 12 * 60 * 1000,        // 12 minutes (exceeds server 10 min timeout)
  uploadTimeout: 15 * 60 * 1000,     // 15 minutes for multipart uploads (extra margin for large payloads)
  downloadTimeout: 60 * 1000,        // 1 minute for file downloads (Azure Blob Storage should be fast)
  connectTimeout: 30 * 1000,         // 30 seconds for socket connection
  keepAliveInterval: 30 * 1000,      // 30 seconds keep-alive probe interval
  maxSockets: 10,                    // Max 10 concurrent sockets per host
  maxFreeSockets: 10,                // Keep 10 idle sockets alive
};

export function createHttpAgent(config: HttpTimeoutConfig = DEFAULT_TIMEOUT_CONFIG): http.Agent {
  return new http.Agent({
    keepAlive: true,
    keepAliveMsecs: config.keepAliveInterval,
    timeout: config.apiTimeout,
    maxSockets: config.maxSockets,
    maxFreeSockets: config.maxFreeSockets,
  });
}

export function createHttpsAgent(config: HttpTimeoutConfig = DEFAULT_TIMEOUT_CONFIG): https.Agent {
  return new https.Agent({
    keepAlive: true,
    keepAliveMsecs: config.keepAliveInterval,
    timeout: config.apiTimeout,
    maxSockets: config.maxSockets,
    maxFreeSockets: config.maxFreeSockets,
  });
}

export interface AxiosConfigOptions {
  /** API base URL */
  baseURL: string;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Timeout configuration for agents */
  timeoutConfig?: HttpTimeoutConfig;
  /** Custom user agent string to append to default SDK user agent */
  userAgent?: string;
}

export function createAxiosConfig(
  baseURL: string,
  timeout: number = DEFAULT_TIMEOUT_CONFIG.apiTimeout,
  config: HttpTimeoutConfig = DEFAULT_TIMEOUT_CONFIG,
  userAgent?: string
): AxiosRequestConfig {
  return {
    baseURL,
    timeout,
    httpAgent: createHttpAgent(config),
    httpsAgent: createHttpsAgent(config),
    headers: {
      'User-Agent': buildUserAgent(userAgent),
      'X-SDK-Version': SDK_VERSION,
    },
  };
}

export function configureRetryInterceptor(
  axiosInstance: AxiosInstance,
  retryConfig?: RetryConfig
): void {
  addRetryInterceptor(axiosInstance, retryConfig);
}

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
