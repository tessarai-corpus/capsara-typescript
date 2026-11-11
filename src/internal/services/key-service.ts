/** Party key management for fetching public keys. */

import axios, { AxiosInstance } from 'axios';
import type { PartyKey } from '../../types/index.js';
import { CapsaraError } from '../../errors/capsara-error.js';
import {
  createAxiosConfig,
  configureRetryInterceptor,
  DEFAULT_TIMEOUT_CONFIG,
  type HttpTimeoutConfig,
} from '../config/http-client.js';
import type { RetryConfig } from '../config/retry-interceptor.js';
import { addTokenRefreshInterceptor, type TokenRefresher } from '../config/token-refresh.js';

export const MAX_PARTY_IDS_PER_REQUEST = 500;

export interface KeyManagerOptions {
  timeout?: Partial<HttpTimeoutConfig>;
  retry?: RetryConfig;
  tokenRefresher?: TokenRefresher;
  userAgent?: string;
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
      timeoutConfig,
      options?.userAgent
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

    if (options?.tokenRefresher) {
      addTokenRefreshInterceptor(this.axiosInstance, options.tokenRefresher);
    }
  }

  async fetchPartyKeys(partyIds: string[]): Promise<PartyKey[]> {
    const ids = Array.from(new Set(partyIds));
    const parties = new Map<string, PartyKey>();

    for (let start = 0; start < ids.length; start += MAX_PARTY_IDS_PER_REQUEST) {
      let data: unknown;
      try {
        const response = await this.axiosInstance.post<unknown>(
          '/api/party/keys',
          { ids: ids.slice(start, start + MAX_PARTY_IDS_PER_REQUEST) }
        );
        data = response.data;
      } catch (error) {
        throw CapsaraError.fromApiError(error);
      }
      if (typeof data !== 'object' || data === null || Array.isArray(data)) {
        throw new CapsaraError('The server returned an unexpected party keys response body.', 'INVALID_RESPONSE', 0);
      }
      const received = (data as { parties?: unknown }).parties;
      for (const party of Array.isArray(received) ? (received as PartyKey[]) : []) {
        const existing = parties.get(party.id);
        parties.set(party.id, existing ? mergePartyKey(existing, party) : party);
      }
    }

    return Array.from(parties.values());
  }
}

function mergePartyKey(existing: PartyKey, next: PartyKey): PartyKey {
  const actingFor = [existing.isDelegate, next.isDelegate].flatMap(value => (Array.isArray(value) ? value : []));
  if (actingFor.length === 0) {
    return existing.isDelegate === undefined && next.isDelegate !== undefined ? { ...existing, isDelegate: next.isDelegate } : existing;
  }
  return { ...existing, isDelegate: Array.from(new Set(actingFor)) };
}
