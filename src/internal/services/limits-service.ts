/** System limits management with caching. */

import axios, { AxiosInstance } from 'axios';
import type { SystemLimits } from '../../types/index.js';
import {
  createAxiosConfig,
  configureRetryInterceptor,
  DEFAULT_TIMEOUT_CONFIG,
  type HttpTimeoutConfig,
} from '../config/http-client.js';
import type { RetryConfig } from '../config/retry-interceptor.js';

interface CachedLimits {
  limits: SystemLimits;
  cachedAt: number;
  ttl: number;
}

const FALLBACK_LIMITS: SystemLimits = {
  maxFileSize: 50 * 1024 * 1024, // 50MB
  maxFilesPerCapsa: 500, // Matches server's MAX_FILES_PER_CAPSA
  maxTotalSize: 1024 * 1024 * 1024, // 1 GiB per capsa
  maxRequestSize: 2 * 1024 * 1024 * 1024, // 2GB per request, matches MAX_REQUEST_SIZE
  maxRequestFieldBytes: 64 * 1024 * 1024,
  maxFilesPerRequest: 500,
  maxExpirationDays: 3650,
};

export class LimitsManager {
  private axiosInstance: AxiosInstance;
  private cachedLimits: CachedLimits | null = null;
  private readonly cacheTTL: number = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
  private readonly fallbackTTL: number = 60 * 1000;

  constructor(baseUrl: string, timeout?: Partial<HttpTimeoutConfig>, retry?: RetryConfig, userAgent?: string) {
    const timeoutConfig = {
      ...DEFAULT_TIMEOUT_CONFIG,
      ...timeout,
    };

    const axiosConfig = createAxiosConfig(
      baseUrl,
      timeoutConfig.apiTimeout,
      timeoutConfig,
      userAgent
    );
    this.axiosInstance = axios.create(axiosConfig);

    configureRetryInterceptor(this.axiosInstance, retry);
  }

  private async fetchLimits(): Promise<{ limits: SystemLimits; fromApi: boolean }> {
    let data: unknown;
    try {
      data = (await this.axiosInstance.get<unknown>('/api/limits')).data;
    } catch {
      data = undefined;
    }
    if (data !== null && typeof data === 'object' && !Array.isArray(data)) {
      return { limits: data as SystemLimits, fromApi: true };
    }
    return { limits: { ...FALLBACK_LIMITS }, fromApi: false };
  }

  async getLimits(): Promise<SystemLimits> {
    if (this.cachedLimits) {
      const age = Date.now() - this.cachedLimits.cachedAt;

      if (age < this.cachedLimits.ttl) {
        return this.cachedLimits.limits;
      }

      this.cachedLimits = null;
    }

    const { limits, fromApi } = await this.fetchLimits();

    this.cachedLimits = {
      limits,
      cachedAt: Date.now(),
      ttl: fromApi ? this.cacheTTL : this.fallbackTTL,
    };

    return limits;
  }

  clearCache(): void {
    this.cachedLimits = null;
  }

  static getFallbackLimits(): SystemLimits {
    return { ...FALLBACK_LIMITS };
  }
}
