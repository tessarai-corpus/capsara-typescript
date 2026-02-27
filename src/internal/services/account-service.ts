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

export interface PublicKeyInfo {
  publicKey: string;
  keyFingerprint: string;
  createdAt: string;
  isActive: boolean;
}

export interface KeyHistoryEntry {
  publicKey: string;
  keyFingerprint: string;
  createdAt: string;
  revokedAt?: string;
  isActive: boolean;
}

export class AccountClient {
  private axiosInstance: AxiosInstance;

  constructor(baseUrl: string, getToken: () => string | null, timeout?: Partial<HttpTimeoutConfig>, retry?: RetryConfig) {
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

    this.axiosInstance.interceptors.request.use((config) => {
      const token = getToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
  }

  /**
   * Get current active public key
   * @returns Current public key info or null if not set
   */
  async getCurrentPublicKey(): Promise<PublicKeyInfo | null> {
    try {
      const response = await this.axiosInstance.get<{
        publicKey: string | null;
        publicKeyFingerprint: string | null;
      }>('/api/account/key');

      // API returns null fields when no key is configured
      if (!response.data.publicKey) return null;

      return {
        publicKey: response.data.publicKey,
        keyFingerprint: response.data.publicKeyFingerprint ?? '',
        createdAt: '', // API does not return this
        isActive: true,
      };
    } catch (error) {
      // eslint-disable-next-line no-console
      console.warn('Failed to get current public key:', error);
      return null;
    }
  }

  /**
   * Add new public key (auto-rotates: moves current to history)
   *
   * When a new public key is added, the API automatically:
   * - Moves current active key to history
   * - Sets new key as active
   *
   * @param publicKey - New public key in PEM format
   * @param fingerprint - SHA-256 fingerprint of the public key
   * @param reason - Optional reason for key rotation
   * @returns Updated public key info
   * @throws {CapsaraAccountError} If validation error or unauthorized
   */
  async addPublicKey(publicKey: string, fingerprint: string, reason?: string): Promise<PublicKeyInfo> {
    try {
      const response = await this.axiosInstance.post<{
        publicKey: string;
        publicKeyFingerprint: string;
        message?: string;
      }>(
        '/api/account/key',
        {
          publicKey,
          publicKeyFingerprint: fingerprint,
          ...(reason && { reason })
        }
      );

      return {
        publicKey: response.data.publicKey,
        keyFingerprint: response.data.publicKeyFingerprint,
        createdAt: new Date().toISOString(), // API doesn't return this, use current time
        isActive: true, // Newly added keys are always active
      };
    } catch (error) {
      throw CapsaraAccountError.fromApiError(error as import('../../errors/capsara-error.js').AxiosLikeError);
    }
  }

  /**
   * Get key history (all previous keys)
   * @returns Array of historical keys (including current active key)
   */
  async getKeyHistory(): Promise<KeyHistoryEntry[]> {
    try {
      const response = await this.axiosInstance.get<{
        keyHistory: Array<{
          keyFingerprint: string;
          rotatedAt: string;
          rotatedBy: string;
          reason?: string;
          envelopesAffected: number;
        }>;
        total: number;
      }>('/api/account/key/history');

      return (response.data.keyHistory ?? []).map(e => ({
        publicKey: '', // API does not return public key in history
        keyFingerprint: e.keyFingerprint,
        createdAt: e.rotatedAt, // Best approximation: when the key was rotated out
        revokedAt: e.rotatedAt,
        isActive: false,
      }));
    } catch (error) {
      // eslint-disable-next-line no-console
      console.warn('Failed to get key history:', error);
      return [];
    }
  }

  /**
   * Rotate key: generate new key pair and update on server.
   * Application must store the returned private key securely.
   * The private key is never sent to the server.
   * @returns New key pair and updated server info
   */
  async rotateKey(): Promise<{
    keyPair: GeneratedKeyPair;
    serverInfo: PublicKeyInfo;
  }> {
    const keyPair = await generateKeyPair();
    const serverInfo = await this.addPublicKey(keyPair.publicKey, keyPair.publicKeyFingerprint);

    return {
      keyPair,
      serverInfo,
    };
  }
}
