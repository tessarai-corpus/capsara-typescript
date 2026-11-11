/** Account management client for key rotation and account operations. */

import axios, { AxiosInstance } from 'axios';
import { generateKeyPair, type GeneratedKeyPair } from '../crypto/key-generator.js';
import { CapsaraAccountError } from '../../errors/account-error.js';
import {
  createAxiosConfig,
  configureRetryInterceptor,
  DEFAULT_TIMEOUT_CONFIG,
  type HttpTimeoutConfig,
} from '../config/http-client.js';
import type { RetryConfig } from '../config/retry-interceptor.js';
import { addTokenRefreshInterceptor, type TokenRefresher } from '../config/token-refresh.js';

export interface PublicKeyInfo {
  publicKey: string;
  keyFingerprint: string;
  createdAt: string;
  isActive: boolean;
}

export interface KeyHistoryEntry {
  keyFingerprint: string;
  rotatedAt: string;
  rotatedBy: string;
  reason?: string;
  envelopesAffected: number | null;
}

export interface RotateKeyOptions {
  onKeyPairGenerated?: (keyPair: GeneratedKeyPair) => void | Promise<void>;
  reason?: string;
}

function requireObject<T>(data: unknown): T {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new CapsaraAccountError('The server returned an unexpected response body.', 'INVALID_RESPONSE', 0);
  }
  return data as T;
}

export class AccountClient {
  private axiosInstance: AxiosInstance;

  constructor(
    baseUrl: string,
    getToken: () => string | null,
    timeout?: Partial<HttpTimeoutConfig>,
    retry?: RetryConfig,
    tokenRefresher?: TokenRefresher,
    userAgent?: string
  ) {
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

    this.axiosInstance.interceptors.request.use((config) => {
      const token = getToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    if (tokenRefresher) {
      addTokenRefreshInterceptor(this.axiosInstance, tokenRefresher);
    }
  }

  async getCurrentPublicKey(): Promise<PublicKeyInfo | null> {
    let data: { publicKey?: string | null; publicKeyFingerprint?: string | null };
    try {
      const response = await this.axiosInstance.get<unknown>('/api/account/key');
      data = requireObject<typeof data>(response.data);
    } catch (error) {
      throw CapsaraAccountError.fromApiError(error);
    }

    if (!data.publicKey) return null;

    return {
      publicKey: data.publicKey,
      keyFingerprint: data.publicKeyFingerprint ?? '',
      createdAt: '', // API does not return this
      isActive: true,
    };
  }

  async addPublicKey(publicKey: string, fingerprint: string, reason?: string): Promise<PublicKeyInfo> {
    try {
      const response = await this.axiosInstance.post<unknown>(
        '/api/account/key',
        {
          publicKey,
          publicKeyFingerprint: fingerprint,
          ...(reason && { reason })
        }
      );
      const data = requireObject<{ publicKey: string; publicKeyFingerprint: string }>(response.data);

      return {
        publicKey: data.publicKey,
        keyFingerprint: data.publicKeyFingerprint,
        createdAt: new Date().toISOString(), // API doesn't return this, use current time
        isActive: true, // Newly added keys are always active
      };
    } catch (error) {
      throw CapsaraAccountError.fromApiError(error);
    }
  }

  async getKeyHistory(): Promise<KeyHistoryEntry[]> {
    try {
      const response = await this.axiosInstance.get<unknown>('/api/account/key/history');
      const data = requireObject<{ keyHistory?: KeyHistoryEntry[] | null }>(response.data);

      return (data.keyHistory ?? []).map(e => ({
        keyFingerprint: e.keyFingerprint,
        rotatedAt: e.rotatedAt,
        rotatedBy: e.rotatedBy,
        ...(e.reason !== undefined && e.reason !== null && { reason: e.reason }),
        envelopesAffected: e.envelopesAffected ?? null,
      }));
    } catch (error) {
      throw CapsaraAccountError.fromApiError(error);
    }
  }

  async rotateKey(options?: RotateKeyOptions): Promise<{
    keyPair: GeneratedKeyPair;
    serverInfo: PublicKeyInfo;
  }> {
    const keyPair = await generateKeyPair();
    if (options?.onKeyPairGenerated) {
      await options.onKeyPairGenerated(keyPair);
    }
    const serverInfo = await this.addPublicKey(keyPair.publicKey, keyPair.publicKeyFingerprint, options?.reason);

    return {
      keyPair,
      serverInfo,
    };
  }
}
