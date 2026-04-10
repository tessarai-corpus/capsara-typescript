/**
 * Unified retry executor - eliminates retry logic duplication
 * @file capsara.sdk/typescript/src/internal/retry-executor.ts
 *
 * This module provides a unified retry mechanism that can be used for:
 * - Axios HTTP requests (via interceptor in http-factory)
 * - Raw HTTP/HTTPS requests (for multipart uploads)
 * - Generic async operations
 */

import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { createAgentForProtocol, type HttpTimeoutConfig, DEFAULT_TIMEOUT_CONFIG } from './http-factory.js';

/**
 * Logger interface for retry operations
 */
export interface RetryLogger {
  log: (message: string) => void;
}

/**
 * Retry configuration
 */
export interface RetryConfig {
  maxRetries?: number;
  baseDelay?: number;
  maxDelay?: number;
  enableLogging?: boolean;
  logger?: RetryLogger;
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
 * Calculate exponential backoff delay with jitter
 */
function calculateBackoff(attempt: number, baseDelay: number, maxDelay: number): number {
  const exponentialDelay = baseDelay * Math.pow(2, attempt);
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
 * Check if HTTP status is retryable
 */
function isRetryableStatus(status: number): boolean {
  return status === 503 || status === 429;
}

/**
 * Parse retry delay from response headers
 */
function parseRetryDelay(headers: http.IncomingHttpHeaders): number | null {
  const retryAfter = headers['retry-after'];
  if (!retryAfter || typeof retryAfter !== 'string') {
    return null;
  }

  const seconds = parseInt(retryAfter, 10);
  if (!isNaN(seconds)) {
    return seconds * 1000;
  }

  const date = new Date(retryAfter);
  if (!isNaN(date.getTime())) {
    const delay = date.getTime() - Date.now();
    return delay > 0 ? delay : 0;
  }

  return null;
}

/**
 * Options for raw HTTP requests
 */
export interface RawHttpOptions {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  headers?: Record<string, string>;
  body?: Buffer | string;
  timeout?: number;
  timeoutConfig?: HttpTimeoutConfig;
}

/**
 * Response from raw HTTP request
 */
export interface RawHttpResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

/**
 * Unified retry executor for both axios and raw HTTP requests
 */
export class RetryExecutor {
  private config: Required<RetryConfig>;

  constructor(config: RetryConfig = {}) {
    this.config = { ...DEFAULT_RETRY_CONFIG, ...config };
  }

  /**
   * Execute a generic async operation with retry
   */
  async execute<T>(
    operation: () => Promise<T>,
    isRetryable?: (error: unknown) => boolean
  ): Promise<T> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;

        // Check if we should retry
        if (attempt >= this.config.maxRetries) {
          break;
        }

        // Default: retry on any error; custom function can override
        const shouldRetry = isRetryable ? isRetryable(error) : true;
        if (!shouldRetry) {
          break;
        }

        const delay = calculateBackoff(attempt, this.config.baseDelay, this.config.maxDelay);
        if (this.config.enableLogging) {
          this.config.logger.log(
            `[Capsara SDK] Retry ${attempt + 1}/${this.config.maxRetries} - waiting ${delay}ms`
          );
        }

        await sleep(delay);
      }
    }

    throw lastError;
  }

  /**
   * Execute a raw HTTP request with retry (for multipart uploads)
   *
   * This replaces the duplicated retry logic in:
   * - CapsaraClient#sendCapsasWithRetry (121 lines)
   * - CapsaraClient#downloadFileWithRetry (54 lines)
   */
  async executeRawHttp(options: RawHttpOptions): Promise<RawHttpResponse> {
    let lastError: unknown;
    let lastResponse: RawHttpResponse | null = null;

    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      try {
        const response = await this.makeRawRequest(options);
        lastResponse = response;

        // Check if response indicates a retryable error
        if (isRetryableStatus(response.statusCode)) {
          if (attempt >= this.config.maxRetries) {
            // Return the response even on error (caller can check statusCode)
            return response;
          }

          // Get delay from server or use backoff
          const serverDelay = parseRetryDelay(response.headers);
          const delay = serverDelay !== null
            ? Math.min(serverDelay, this.config.maxDelay)
            : calculateBackoff(attempt, this.config.baseDelay, this.config.maxDelay);

          if (this.config.enableLogging) {
            this.config.logger.log(
              `[Capsara SDK] Retry ${attempt + 1}/${this.config.maxRetries} for ${response.statusCode} - waiting ${delay}ms`
            );
          }

          await sleep(delay);
          continue;
        }

        return response;
      } catch (error) {
        lastError = error;

        if (attempt >= this.config.maxRetries) {
          break;
        }

        const delay = calculateBackoff(attempt, this.config.baseDelay, this.config.maxDelay);
        if (this.config.enableLogging) {
          this.config.logger.log(
            `[Capsara SDK] Retry ${attempt + 1}/${this.config.maxRetries} (network error) - waiting ${delay}ms`
          );
        }

        await sleep(delay);
      }
    }

    // Return last response if we have one, otherwise throw
    if (lastResponse) {
      return lastResponse;
    }
    throw lastError;
  }

  /**
   * Make a single raw HTTP request
   */
  private makeRawRequest(options: RawHttpOptions): Promise<RawHttpResponse> {
    return new Promise((resolve, reject) => {
      const url = new URL(options.url);
      const timeout = options.timeout ?? DEFAULT_TIMEOUT_CONFIG.uploadTimeout;
      const timeoutConfig = options.timeoutConfig ?? DEFAULT_TIMEOUT_CONFIG;

      const requestModule = url.protocol === 'https:' ? https : http;
      const agent = createAgentForProtocol(url.protocol, timeout, timeoutConfig);

      const requestOptions: http.RequestOptions = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: options.method,
        headers: options.headers,
        agent,
        timeout,
      };

      const req = requestModule.request(requestOptions, (res) => {
        const chunks: Buffer[] = [];

        res.on('data', (chunk: Buffer) => {
          chunks.push(chunk);
        });

        res.on('end', () => {
          resolve({
            statusCode: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks),
          });
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Request timeout after ${timeout}ms`));
      });

      if (options.body) {
        req.write(options.body);
      }

      req.end();
    });
  }
}

/**
 * Create a retry executor with default or custom configuration
 */
export function createRetryExecutor(config?: RetryConfig): RetryExecutor {
  return new RetryExecutor(config);
}
