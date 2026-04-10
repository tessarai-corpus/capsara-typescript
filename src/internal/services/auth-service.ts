/** Authentication service for managing access tokens and refresh tokens. */

import type { AxiosInstance } from 'axios';
import type { AuthCredentials, AuthResponse } from '../../types/index.js';
import { CapsaraAuthError } from '../../errors/auth-error.js';
import type { AxiosLikeError } from '../../errors/capsara-error.js';
import { createHttpClient, type HttpTimeoutConfig, type HttpClientOptions } from '../http-factory.js';
import type { RetryConfig } from '../config/retry-interceptor.js';

export type AuthStateChangeCallback = (state: {
  isAuthenticated: boolean;
  event: 'login' | 'logout' | 'refresh' | 'expired';
}) => void;

interface JWTPayload {
  exp?: number;
  iss?: string;
  aud?: string;
  [key: string]: unknown;
}

export interface AuthServiceOptions {
  expectedIssuer?: string;
  expectedAudience?: string;
  timeout?: Partial<HttpTimeoutConfig>;
  retry?: RetryConfig;
  userAgent?: string;
}

export class AuthService {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private tokenExpiresAt: number | null = null;
  private http: AxiosInstance;
  private authStateCallbacks: Set<AuthStateChangeCallback> = new Set();
  private expectedIssuer: string;
  private expectedAudience: string;
  private lastRefreshError: Error | null = null;

  constructor(baseUrl: string, options?: AuthServiceOptions) {
    const httpOptions: HttpClientOptions = {
      baseUrl,
      timeout: options?.timeout,
      retry: options?.retry,
      userAgent: options?.userAgent,
    };
    this.http = createHttpClient(httpOptions);
    this.expectedIssuer = options?.expectedIssuer ?? 'vault.api';
    this.expectedAudience = options?.expectedAudience ?? 'vault.api';
  }

  onAuthChange(callback: AuthStateChangeCallback): void {
    this.authStateCallbacks.add(callback);
  }

  offAuthChange(callback: AuthStateChangeCallback): void {
    this.authStateCallbacks.delete(callback);
  }

  private emitAuthChange(event: 'login' | 'logout' | 'refresh' | 'expired'): void {
    const state = { isAuthenticated: this.isAuthenticated(), event };
    this.authStateCallbacks.forEach((callback) => {
      try {
        callback(state);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error('Auth state callback error:', error);
      }
    });
  }

  private decodeJWT(token: string): JWTPayload | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const payload = parts[1];
      if (!payload) return null;
      const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = Buffer.from(base64, 'base64').toString('utf-8');
      return JSON.parse(jsonPayload) as JWTPayload;
    } catch {
      return null;
    }
  }

  private validateAndExtractExpiry(token: string): number | null {
    const payload = this.decodeJWT(token);
    if (!payload || !payload.exp) return null;
    const expiryMs = payload.exp * 1000;

    if (payload.iss && payload.iss !== this.expectedIssuer) {
      // eslint-disable-next-line no-console
      console.warn(`JWT issuer mismatch: expected '${this.expectedIssuer}', got '${payload.iss}'`);
    }
    if (payload.aud && payload.aud !== this.expectedAudience) {
      // eslint-disable-next-line no-console
      console.warn(`JWT audience mismatch: expected '${this.expectedAudience}', got '${payload.aud}'`);
    }
    return expiryMs;
  }

  isTokenExpired(bufferSeconds = 30): boolean {
    if (!this.tokenExpiresAt) return true;
    return Date.now() >= this.tokenExpiresAt - bufferSeconds * 1000;
  }

  async login(credentials: AuthCredentials): Promise<AuthResponse> {
    try {
      const response = await this.http.post<AuthResponse>('/api/auth/login', credentials);
      this.accessToken = response.data.accessToken;
      this.refreshToken = response.data.refreshToken || null;

      if (response.data.expiresIn) {
        this.tokenExpiresAt = Date.now() + response.data.expiresIn * 1000;
      } else if (response.data.accessToken) {
        this.tokenExpiresAt = this.validateAndExtractExpiry(response.data.accessToken);
      }

      this.emitAuthChange('login');
      return response.data;
    } catch (error) {
      throw CapsaraAuthError.fromApiError(error as AxiosLikeError);
    }
  }

  async refresh(): Promise<boolean> {
    if (!this.refreshToken) return false;

    try {
      const response = await this.http.post<AuthResponse>(
        '/api/auth/refresh',
        { refreshToken: this.refreshToken }
      );
      this.accessToken = response.data.accessToken;
      this.refreshToken = response.data.refreshToken || this.refreshToken;

      if (response.data.expiresIn) {
        this.tokenExpiresAt = Date.now() + response.data.expiresIn * 1000;
      } else if (response.data.accessToken) {
        this.tokenExpiresAt = this.validateAndExtractExpiry(response.data.accessToken);
      }

      this.lastRefreshError = null;
      this.emitAuthChange('refresh');
      return true;
    } catch (error) {
      this.lastRefreshError = error instanceof Error ? error : new Error(String(error));
      // eslint-disable-next-line no-console
      console.warn('Token refresh failed:', error instanceof Error ? error.message : 'Unknown error');
      return false;
    }
  }

  getLastRefreshError(): Error | null {
    return this.lastRefreshError;
  }

  getToken(): string | null {
    return this.accessToken;
  }

  getRefreshToken(): string | null {
    return this.refreshToken;
  }

  isAuthenticated(): boolean {
    return this.accessToken !== null;
  }

  canRefresh(): boolean {
    return this.refreshToken !== null;
  }

  async logout(): Promise<boolean> {
    const currentAccessToken = this.accessToken;
    const currentRefreshToken = this.refreshToken;

    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiresAt = null;

    if (currentAccessToken && currentRefreshToken) {
      try {
        await this.http.post(
          '/api/auth/logout',
          { refreshToken: currentRefreshToken },
          { headers: { Authorization: `Bearer ${currentAccessToken}` } }
        );
        this.emitAuthChange('logout');
        return true;
      } catch (error) {
        // eslint-disable-next-line no-console
        console.warn('Server-side logout failed (tokens cleared locally):', error instanceof Error ? error.message : 'Unknown error');
        this.emitAuthChange('logout');
        return false;
      }
    }

    this.emitAuthChange('logout');
    return true;
  }

  setToken(token: string): void {
    this.accessToken = token;
    this.tokenExpiresAt = this.validateAndExtractExpiry(token);
  }

  setRefreshToken(token: string): void {
    this.refreshToken = token;
  }

  setTokens(accessToken: string, refreshToken: string): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.tokenExpiresAt = this.validateAndExtractExpiry(accessToken);
  }
}
