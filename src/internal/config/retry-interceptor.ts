// Shared HTTP retry policy: 429/503 and dropped connections, honouring server hints, with capped exponential backoff.

import type { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios';

export interface RetryLogger {
  log: (message: string) => void;
}

export interface RetryConfig {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Base delay for exponential backoff in ms (default: 1000) */
  baseDelay?: number;
  /** Maximum delay between retries in ms, server hints included (default: 30000 = 30 seconds) */
  maxDelay?: number;
  /** Enable debug logging for retries (default: false) */
  enableLogging?: boolean;
  /** Custom logger (defaults to console) */
  logger?: RetryLogger;
}

const defaultLogger: RetryLogger = {
  // eslint-disable-next-line no-console
  log: (message: string) => console.log(message),
};

export const DEFAULT_RETRY_CONFIG: Required<RetryConfig> = {
  maxRetries: 3,
  baseDelay: 1000,
  maxDelay: 30000,
  enableLogging: false,
  logger: defaultLogger,
};

export function resolveRetryConfig(config: RetryConfig = {}): Required<RetryConfig> {
  return {
    maxRetries: config.maxRetries ?? DEFAULT_RETRY_CONFIG.maxRetries,
    baseDelay: config.baseDelay ?? DEFAULT_RETRY_CONFIG.baseDelay,
    maxDelay: config.maxDelay ?? DEFAULT_RETRY_CONFIG.maxDelay,
    enableLogging: config.enableLogging ?? DEFAULT_RETRY_CONFIG.enableLogging,
    logger: config.logger ?? DEFAULT_RETRY_CONFIG.logger,
  };
}

export const MAX_SERVER_HINT_MS = 30000;

export function isRetryableStatus(status: number | undefined): boolean {
  return status === 429 || status === 503;
}

export const NETWORK_DROP_CODES: ReadonlySet<string> = new Set([
  'ECONNRESET',
  'EPIPE',
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ENETUNREACH',
  'ENETDOWN',
  'EHOSTUNREACH',
]);

export const TIMEOUT_CODES: ReadonlySet<string> = new Set(['ECONNABORTED', 'ETIMEDOUT', 'ESOCKETTIMEDOUT']);

export type FailureKind = 'status' | 'network' | 'timeout' | 'none';

export function classifyFailure(error: unknown): FailureKind {
  if (typeof error !== 'object' || error === null) return 'none';
  const err = error as { response?: { status?: number }; code?: unknown };
  if (err.response) {
    return isRetryableStatus(err.response.status) ? 'status' : 'none';
  }
  if (typeof err.code !== 'string') return 'none';
  if (NETWORK_DROP_CODES.has(err.code)) return 'network';
  if (TIMEOUT_CODES.has(err.code)) return 'timeout';
  return 'none';
}

export function isRetryableFailure(kind: FailureKind, method: string | undefined): boolean {
  if (kind === 'status' || kind === 'network') return true;
  if (kind === 'timeout') return (method ?? 'get').toLowerCase() !== 'post';
  return false;
}

function parseRetryAfterHeader(retryAfter: string): number | null {
  const trimmed = retryAfter.trim();
  if (/^\d+(\.\d+)?$/.test(trimmed)) {
    return parseFloat(trimmed) * 1000;
  }
  const date = new Date(trimmed);
  if (!isNaN(date.getTime())) {
    return Math.max(date.getTime() - Date.now(), 0);
  }
  return null;
}

function parseBody(data: unknown): unknown {
  if (typeof data !== 'string') return data;
  try {
    return JSON.parse(data) as unknown;
  } catch {
    return undefined;
  }
}

export function getServerSuggestedDelay(data: unknown, headers: unknown): number | null {
  const body = parseBody(data) as { error?: { retryAfter?: unknown } | null } | null | undefined;
  const bodyHint = body && typeof body === 'object' ? body.error?.retryAfter : undefined;
  if (typeof bodyHint === 'number' && Number.isFinite(bodyHint) && bodyHint >= 0) {
    return bodyHint * 1000;
  }

  const headerValue = (headers as Record<string, unknown> | undefined)?.['retry-after'];
  const header: unknown = Array.isArray(headerValue) ? (headerValue as unknown[])[0] : headerValue;
  if (typeof header === 'string' && header.length > 0) {
    return parseRetryAfterHeader(header);
  }
  return null;
}

export function calculateExponentialBackoff(retryCount: number, baseDelay: number, maxDelay: number): number {
  const exponentialDelay = baseDelay * Math.pow(2, retryCount);
  const jitter = Math.random() * 0.3 * exponentialDelay;
  return Math.floor(Math.min(exponentialDelay + jitter, maxDelay));
}

export function computeRetryDelay(
  retryCount: number,
  serverDelay: number | null,
  config: Required<RetryConfig>
): { delay: number; source: 'server suggested' | 'exponential backoff' } {
  if (serverDelay !== null) {
    return { delay: Math.min(serverDelay, config.maxDelay, MAX_SERVER_HINT_MS), source: 'server suggested' };
  }
  return {
    delay: calculateExponentialBackoff(retryCount, config.baseDelay, config.maxDelay),
    source: 'exponential backoff',
  };
}

export function describeFailure(error: unknown): string {
  const err = error as { response?: { status?: number }; code?: string };
  if (err?.response?.status) return String(err.response.status);
  return err?.code ?? 'network error';
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => globalThis.setTimeout(resolve, ms));
}

interface AxiosConfigWithRetry extends InternalAxiosRequestConfig {
  __retryCount?: number;
}

export function addRetryInterceptor(
  axiosInstance: AxiosInstance,
  config: RetryConfig = {}
): void {
  const retryConfig = resolveRetryConfig(config);

  axiosInstance.interceptors.response.use(
    (response) => response,

    async (error: AxiosError) => {
      const requestConfig = error.config as AxiosConfigWithRetry | undefined;

      if (!requestConfig) {
        return Promise.reject(error instanceof Error ? error : new Error(String(error)));
      }

      requestConfig.__retryCount ??= 0;

      const kind = classifyFailure(error);
      if (!isRetryableFailure(kind, requestConfig.method) || requestConfig.__retryCount >= retryConfig.maxRetries) {
        return Promise.reject(error);
      }

      const serverDelay = error.response ? getServerSuggestedDelay(error.response.data, error.response.headers) : null;
      const { delay, source } = computeRetryDelay(requestConfig.__retryCount, serverDelay, retryConfig);
      requestConfig.__retryCount++;

      if (retryConfig.enableLogging) {
        retryConfig.logger.log(
          `[Capsara SDK] Retry attempt ${requestConfig.__retryCount}/${retryConfig.maxRetries} ` +
          `for ${describeFailure(error)} - waiting ${delay}ms (${source})`
        );
      }

      await sleep(delay);
      return axiosInstance.request(requestConfig);
    }
  );
}
