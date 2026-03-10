/** Party key management for fetching public keys. */

import axios, { AxiosInstance } from 'axios';
import type { PartyKey } from '../../types/index.js';
import {
  createAxiosConfig,
  configureRetryInterceptor,
  DEFAULT_TIMEOUT_CONFIG,
  type HttpTimeoutConfig,
} from '../config/http-client.js';
import type { RetryConfig } from '../config/retry-interceptor.js';

export interface KeyManagerOptions {
  timeout?: Partial<HttpTimeoutConfig>;
  retry?: RetryConfig;
}

export class KeyManager {
  private axiosInstance: AxiosInstance;

  constructor(
    baseUrl: string,
    getToken: () => string | null,
    options?: KeyManagerOptions
  ) {
    const timeoutConfig = {
      ...DEFAULT_TIMEOUT_CONFIG,
      ...options?.timeout,
    };

    const axiosConfig = createAxiosConfig(
      baseUrl,
      timeoutConfig.apiTimeout,
      timeoutConfig
    );
    this.axiosInstance = axios.create(axiosConfig);

    configureRetryInterceptor(this.axiosInstance, options?.retry);

    this.axiosInstance.interceptors.request.use((config) => {
      const token = getToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
  }

  /**
   * Fetch a single party key by exact ID (excludes delegates)
   * Always fetches fresh from API to handle remote key rotations
   * @param partyId - Party ID to fetch
   * @returns Party key or undefined if not found
   */
  async fetchExplicitPartyKey(partyId: string): Promise<PartyKey | undefined> {
    const response = await this.axiosInstance.post<{ parties: PartyKey[] }>(
      '/api/party/keys',
      { ids: [partyId] }
    );

    // Return only the explicitly requested party (API may include delegates)
    return response.data.parties.find((p) => p.id === partyId);
  }

  /**
   * Fetch party keys from API (includes delegates)
   * Always fetches fresh from API to handle remote key rotations
   * Uses POST to avoid URL length limits with large batches
   * @param partyIds - Array of party IDs
   * @returns Array of party keys with public keys and fingerprints (includes delegates)
   */
  async fetchPartyKeys(partyIds: string[]): Promise<PartyKey[]> {
    const response = await this.axiosInstance.post<{ parties: PartyKey[] }>(
      '/api/party/keys',
      { ids: partyIds }
    );

    return response.data.parties;
  }
}
