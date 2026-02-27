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
}

/**
 * Hardcoded fallback limits (used if API fetch fails)
 * These MUST match the server's FileConstraints in vault.api/src/types/upload.types.ts
 */
const FALLBACK_LIMITS: SystemLimits = {
  maxFileSize: 50 * 1024 * 1024, // 50MB
  maxFilesPerCapsa: 500, // Matches server's MAX_FILES_PER_CAPSA
  maxTotalSize: 500 * 1024 * 1024, // 500MB
};

export class LimitsManager {
  private axiosInstance: AxiosInstance;
  private cachedLimits: CachedLimits | null = null;
  private readonly cacheTTL: number = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

  constructor(baseUrl: string, timeout?: Partial<HttpTimeoutConfig>, retry?: RetryConfig) {
    const timeoutConfig = {
      ...DEFAULT_TIMEOUT_CONFIG,
      ...timeout,
    };

    const axiosConfig = createAxiosConfig(
      baseUrl,
      timeoutConfig.apiTimeout,
      timeoutConfig
    );
    this.axiosInstance = axios.create(axiosConfig);

    configureRetryInterceptor(this.axiosInstance, retry);
  }

  /**
   * Fetch system limits from API
   * @returns System limits
   */
  private async fetchLimits(): Promise<SystemLimits> {
    try {
      const response = await this.axiosInstance.get<SystemLimits>('/api/limits');
      return response.data;
    } catch {
      // API is down or /limits endpoint doesn't exist - use fallback
      return FALLBACK_LIMITS;
    }
  }

  /**
   * Get system limits (from cache or fetch from API)
   * @returns System limits
   */
  async getLimits(): Promise<SystemLimits> {
    if (this.cachedLimits) {
      const age = Date.now() - this.cachedLimits.cachedAt;

      if (age < this.cacheTTL) {
        return this.cachedLimits.limits;
      }

      this.cachedLimits = null;
    }

    const limits = await this.fetchLimits();

    this.cachedLimits = {
      limits,
      cachedAt: Date.now(),
    };

    return limits;
  }

  /**
   * Clear the limits cache (useful for testing or forcing refresh)
   */
  clearCache(): void {
    this.cachedLimits = null;
  }

  /**
   * Get fallback limits (for reference)
   * @returns Hardcoded fallback limits
   */
  static getFallbackLimits(): SystemLimits {
    return { ...FALLBACK_LIMITS };
  }
}
