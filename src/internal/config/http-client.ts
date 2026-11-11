// HTTP client configuration with timeout and keep-alive settings.

import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import type * as stream from 'stream';
import * as tls from 'tls';
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
// API server timeout: 10 min request, 11 min keepAlive.
export const DEFAULT_TIMEOUT_CONFIG: HttpTimeoutConfig = {
  apiTimeout: 12 * 60 * 1000,        // 12 minutes (exceeds server 10 min timeout)
  uploadTimeout: 15 * 60 * 1000,     // 15 minutes for multipart uploads (extra margin for large payloads)
  downloadTimeout: 60 * 1000,        // 1 minute for file downloads (Azure Blob Storage should be fast)
  connectTimeout: 30 * 1000,         // 30 seconds for socket connection
  keepAliveInterval: 30 * 1000,      // 30 seconds keep-alive probe interval
  maxSockets: 10,                    // Max 10 concurrent sockets per host
  maxFreeSockets: 10,                // Keep 10 idle sockets alive
};

const MAX_TIMER_MS = 2_147_483_647;

function guardConnect(socket: stream.Duplex | null | undefined, connectTimeout: number): stream.Duplex | null | undefined {
  if (!(socket instanceof net.Socket) || !socket.connecting) return socket;
  if (!(connectTimeout > 0 && connectTimeout <= MAX_TIMER_MS)) return socket;

  const readyEvent = socket instanceof tls.TLSSocket ? 'secureConnect' : 'connect';
  const timer = globalThis.setTimeout(() => {
    socket.destroy(Object.assign(new Error(`Connection timed out after ${connectTimeout} ms`), { code: 'ETIMEDOUT' }));
  }, connectTimeout);
  const clear = () => globalThis.clearTimeout(timer);
  socket.once(readyEvent, clear);
  socket.once('close', clear);
  return socket;
}

class ConnectTimeoutHttpAgent extends http.Agent {
  readonly #connectTimeout: number;

  constructor(options: http.AgentOptions, connectTimeout: number) {
    super(options);
    this.#connectTimeout = connectTimeout;
  }

  override createConnection(
    options: http.ClientRequestArgs,
    callback?: (err: Error | null, stream: stream.Duplex) => void
  ): stream.Duplex | null | undefined {
    return guardConnect(super.createConnection(options, callback), this.#connectTimeout);
  }
}

class ConnectTimeoutHttpsAgent extends https.Agent {
  readonly #connectTimeout: number;

  constructor(options: https.AgentOptions, connectTimeout: number) {
    super(options);
    this.#connectTimeout = connectTimeout;
  }

  override createConnection(
    options: http.ClientRequestArgs,
    callback?: (err: Error | null, stream: stream.Duplex) => void
  ): stream.Duplex | null | undefined {
    return guardConnect(super.createConnection(options, callback), this.#connectTimeout);
  }
}

function agentOptions(timeout: number, config: HttpTimeoutConfig): http.AgentOptions {
  return {
    keepAlive: true,
    keepAliveMsecs: config.keepAliveInterval,
    timeout,
    maxSockets: config.maxSockets,
    maxFreeSockets: config.maxFreeSockets,
  };
}

export function createHttpAgent(config: HttpTimeoutConfig = DEFAULT_TIMEOUT_CONFIG): http.Agent {
  return new ConnectTimeoutHttpAgent(agentOptions(config.apiTimeout, config), config.connectTimeout);
}

export function createHttpsAgent(config: HttpTimeoutConfig = DEFAULT_TIMEOUT_CONFIG): https.Agent {
  return new ConnectTimeoutHttpsAgent(agentOptions(config.apiTimeout, config), config.connectTimeout);
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
  return protocol === 'https:'
    ? new ConnectTimeoutHttpsAgent(agentOptions(timeout, config), config.connectTimeout)
    : new ConnectTimeoutHttpAgent(agentOptions(timeout, config), config.connectTimeout);
}
