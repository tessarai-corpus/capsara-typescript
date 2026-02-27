// Axios retry interceptor for 503 and 429 errors with exponential backoff.

import type { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios';

export interface RetryLogger {
  log: (message: string) => void;
}

export interface RetryConfig {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Base delay for exponential backoff in ms (default: 1000) */
  baseDelay?: number;
  /** Maximum delay between retries in ms (default: 30000 = 30 seconds) */
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

const DEFAULT_RETRY_CONFIG: Required<RetryConfig> = {
  maxRetries: 3,
  baseDelay: 1000,     // 1 second base delay
  maxDelay: 30000,     // 30 seconds max delay
  enableLogging: false,
  logger: defaultLogger,
};

interface AxiosConfigWithRetry extends InternalAxiosRequestConfig {
  __retryCount?: number;
}

/** Parses Retry-After header as seconds or HTTP date, returns delay in ms. */
function parseRetryAfterHeader(retryAfter: string | undefined): number | null {
  if (!retryAfter) return null;

  const seconds = parseInt(retryAfter, 10);
  if (!isNaN(seconds)) {
    return seconds * 1000;
  }

  // Try parsing as HTTP date
  const date = new Date(retryAfter);
  if (!isNaN(date.getTime())) {
    const delay = date.getTime() - Date.now();
    return delay > 0 ? delay : 0;
  }

  return null;
}

function calculateExponentialBackoff(retryCount: number, baseDelay: number, maxDelay: number): number {
  // baseDelay * 2^retryCount with +30% jitter
  const exponentialDelay = baseDelay * Math.pow(2, retryCount);
  const jitter = Math.random() * 0.3 * exponentialDelay;
  const delay = Math.min(exponentialDelay + jitter, maxDelay);
  return Math.floor(delay);
}

interface ErrorResponseData {
  error?: {
    retryAfter?: number;
  };
}

function hasRetryAfter(data: unknown): data is ErrorResponseData {
  return (
    typeof data === 'object' &&
    data !== null &&
    'error' in data &&
    typeof (data as ErrorResponseData).error === 'object' &&
    (data as ErrorResponseData).error !== null &&
    'retryAfter' in ((data as ErrorResponseData).error as object)
  );
}

/** Extracts retry delay from response body (error.retryAfter) or Retry-After header. */
function getServerSuggestedDelay(error: AxiosError): number | null {
  const responseData = error.response?.data;
  if (hasRetryAfter(responseData)) {
    const retryAfter = responseData.error?.retryAfter;
    if (typeof retryAfter === 'number') {
      return retryAfter * 1000;
    }
  }

  const headers = error.response?.headers as Record<string, string> | undefined;
  const retryAfterHeader = headers?.['retry-after'];
  if (retryAfterHeader && typeof retryAfterHeader === 'string') {
    return parseRetryAfterHeader(retryAfterHeader);
  }

  return null;
}

function isRetryableError(error: AxiosError): boolean {
  if (!error.response) return false;
  const status = error.response.status;
  return status === 503 || status === 429;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => globalThis.setTimeout(resolve, ms));
}

export function addRetryInterceptor(
  axiosInstance: AxiosInstance,
  config: RetryConfig = {}
): void {
  const retryConfig = { ...DEFAULT_RETRY_CONFIG, ...config };

  axiosInstance.interceptors.response.use(
    (response) => response,

    async (error: AxiosError) => {
      const requestConfig = error.config as AxiosConfigWithRetry | undefined;

      if (!requestConfig) {
        return Promise.reject(error);
      }

      if (requestConfig.__retryCount === undefined) {
        requestConfig.__retryCount = 0;
      }

      if (!isRetryableError(error) || requestConfig.__retryCount >= retryConfig.maxRetries) {
        return Promise.reject(error);
      }

      requestConfig.__retryCount++;

      let retryDelay: number;
      const serverDelay = getServerSuggestedDelay(error);

      if (serverDelay !== null) {
        retryDelay = Math.min(serverDelay, retryConfig.maxDelay);

        if (retryConfig.enableLogging) {
          retryConfig.logger.log(
            `[Capsara SDK] Retry attempt ${requestConfig.__retryCount}/${retryConfig.maxRetries} ` +
            `for ${error.response?.status} error - waiting ${retryDelay}ms (server suggested)`
          );
        }
      } else {
        retryDelay = calculateExponentialBackoff(
          requestConfig.__retryCount - 1,
          retryConfig.baseDelay,
          retryConfig.maxDelay
        );

        if (retryConfig.enableLogging) {
          retryConfig.logger.log(
            `[Capsara SDK] Retry attempt ${requestConfig.__retryCount}/${retryConfig.maxRetries} ` +
            `for ${error.response?.status} error - waiting ${retryDelay}ms (exponential backoff)`
          );
        }
      }

      await sleep(retryDelay);
      return axiosInstance.request(requestConfig);
    }
  );
}
