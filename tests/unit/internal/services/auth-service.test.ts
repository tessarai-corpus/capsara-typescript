/**
 * Tests for auth-service.ts - Authentication service
 * @file tests/unit/internal/services/auth-service.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { AxiosInstance, AxiosError, AxiosResponse } from 'axios';
import { AuthService, type AuthServiceOptions, type AuthStateChangeCallback } from '../../../../src/internal/services/auth-service.js';
import type { AuthCredentials, AuthResponse } from '../../../../src/types/index.js';

// Mock the http-factory module
vi.mock('../../../../src/internal/http-factory.js', () => ({
  createHttpClient: vi.fn(() => ({
    post: vi.fn(),
    get: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  })),
}));

// Helper to create a valid JWT token
function createMockJWT(payload: Record<string, unknown>, expiresInSeconds = 3600): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const payloadWithDefaults = {
    exp: now + expiresInSeconds,
    iat: now,
    iss: 'vault.api',
    aud: 'vault.api',
    ...payload,
  };
  const payloadBase64 = Buffer.from(JSON.stringify(payloadWithDefaults)).toString('base64url');
  const signature = Buffer.from('mock-signature').toString('base64url');
  return `${header}.${payloadBase64}.${signature}`;
}

// Helper to get the mocked http client
async function getMockedHttpClient(authService: AuthService): Promise<AxiosInstance> {
  const { createHttpClient } = await import('../../../../src/internal/http-factory.js');
  return (createHttpClient as ReturnType<typeof vi.fn>).mock.results[0]?.value as AxiosInstance;
}

describe('AuthService', () => {
  let authService: AuthService;
  let mockHttp: AxiosInstance;

  beforeEach(async () => {
    vi.clearAllMocks();

    // Create auth service
    authService = new AuthService('https://api.example.com');
    mockHttp = await getMockedHttpClient(authService);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should create service with base URL', () => {
      const service = new AuthService('https://api.example.com');
      expect(service).toBeInstanceOf(AuthService);
    });

    it('should create service with options', async () => {
      const { createHttpClient } = await import('../../../../src/internal/http-factory.js');

      const options: AuthServiceOptions = {
        expectedIssuer: 'custom-issuer',
        expectedAudience: 'custom-audience',
        timeout: { apiTimeout: 60000 },
        retry: { maxRetries: 5 },
        userAgent: 'CustomApp/1.0',
      };

      new AuthService('https://api.example.com', options);

      expect(createHttpClient).toHaveBeenCalledWith({
        baseUrl: 'https://api.example.com',
        timeout: { apiTimeout: 60000 },
        retry: { maxRetries: 5 },
        userAgent: 'CustomApp/1.0',
      });
    });
  });

  describe('login', () => {
    it('should login with valid credentials', async () => {
      const mockToken = createMockJWT({ sub: 'party_123' });
      const mockResponse: AuthResponse = {
        accessToken: mockToken,
        refreshToken: 'refresh_token',
        expiresIn: 3600,
        party: {
          id: 'party_123',
          email: 'test@example.com',
          name: 'Test User',
          kind: 'person',
        },
      };

      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValue({ data: mockResponse });

      const credentials: AuthCredentials = {
        email: 'test@example.com',
        password: 'password123',
      };

      const result = await authService.login(credentials);

      expect(result).toEqual(mockResponse);
      expect(authService.getToken()).toBe(mockToken);
      expect(authService.getRefreshToken()).toBe('refresh_token');
      expect(authService.isAuthenticated()).toBe(true);
    });

    it('should extract expiry from token when expiresIn is not provided', async () => {
      const mockToken = createMockJWT({ sub: 'party_123' }, 7200);
      const mockResponse: AuthResponse = {
        accessToken: mockToken,
        refreshToken: 'refresh_token',
        expiresIn: 0, // Falsy, should use token expiry
        party: {
          id: 'party_123',
          email: 'test@example.com',
          name: 'Test User',
          kind: 'person',
        },
      };

      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValue({ data: mockResponse });

      await authService.login({ email: 'test@example.com', password: 'pass' });

      expect(authService.isAuthenticated()).toBe(true);
    });

    it('should emit login event', async () => {
      const mockToken = createMockJWT({ sub: 'party_123' });
      const mockResponse: AuthResponse = {
        accessToken: mockToken,
        refreshToken: 'refresh_token',
        expiresIn: 3600,
        party: {
          id: 'party_123',
          email: 'test@example.com',
          name: 'Test User',
          kind: 'person',
        },
      };

      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValue({ data: mockResponse });

      const callback = vi.fn();
      authService.onAuthChange(callback);

      await authService.login({ email: 'test@example.com', password: 'pass' });

      expect(callback).toHaveBeenCalledWith({
        isAuthenticated: true,
        event: 'login',
      });
    });

    it('should throw CapsaraAuthError on login failure', async () => {
      const error = new Error('Invalid credentials') as AxiosError;
      error.response = {
        status: 401,
        statusText: 'Unauthorized',
        data: { error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials' } },
        headers: {},
        config: {} as AxiosError['config'],
      };
      (mockHttp.post as ReturnType<typeof vi.fn>).mockRejectedValue(error);

      await expect(authService.login({ email: 'test@example.com', password: 'wrong' })).rejects.toThrow();
    });
  });

  describe('refresh', () => {
    it('should refresh token when refresh token exists', async () => {
      // First login
      const mockToken = createMockJWT({ sub: 'party_123' });
      const loginResponse: AuthResponse = {
        accessToken: mockToken,
        refreshToken: 'refresh_token',
        expiresIn: 3600,
        party: {
          id: 'party_123',
          email: 'test@example.com',
          name: 'Test User',
          kind: 'person',
        },
      };
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: loginResponse });
      await authService.login({ email: 'test@example.com', password: 'pass' });

      // Then refresh
      const newToken = createMockJWT({ sub: 'party_123' }, 7200);
      const refreshResponse: AuthResponse = {
        accessToken: newToken,
        refreshToken: 'new_refresh_token',
        expiresIn: 7200,
        party: {
          id: 'party_123',
          email: 'test@example.com',
          name: 'Test User',
          kind: 'person',
        },
      };
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: refreshResponse });

      const result = await authService.refresh();

      expect(result).toBe(true);
      expect(authService.getToken()).toBe(newToken);
      expect(authService.getRefreshToken()).toBe('new_refresh_token');
    });

    it('should return false when no refresh token exists', async () => {
      const result = await authService.refresh();

      expect(result).toBe(false);
      expect(mockHttp.post).not.toHaveBeenCalled();
    });

    it('should keep existing refresh token if new one not provided', async () => {
      // Setup with token
      authService.setTokens(createMockJWT({}), 'original_refresh');

      const refreshResponse: AuthResponse = {
        accessToken: createMockJWT({}),
        refreshToken: '', // Empty
        expiresIn: 3600,
        party: {
          id: 'party_123',
          email: 'test@example.com',
          name: 'Test User',
          kind: 'person',
        },
      };
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: refreshResponse });

      await authService.refresh();

      expect(authService.getRefreshToken()).toBe('original_refresh');
    });

    it('should emit refresh event on success', async () => {
      authService.setTokens(createMockJWT({}), 'refresh_token');

      const refreshResponse: AuthResponse = {
        accessToken: createMockJWT({}),
        refreshToken: 'new_refresh',
        expiresIn: 3600,
        party: {
          id: 'party_123',
          email: 'test@example.com',
          name: 'Test User',
          kind: 'person',
        },
      };
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: refreshResponse });

      const callback = vi.fn();
      authService.onAuthChange(callback);

      await authService.refresh();

      expect(callback).toHaveBeenCalledWith({
        isAuthenticated: true,
        event: 'refresh',
      });
    });

    it('should return false on refresh error', async () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      authService.setTokens(createMockJWT({}), 'refresh_token');

      (mockHttp.post as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Refresh failed'));

      const result = await authService.refresh();

      expect(result).toBe(false);
      expect(warnSpy).toHaveBeenCalledWith('Token refresh failed:', expect.any(String));

      warnSpy.mockRestore();
    });

    it('should store last refresh error', async () => {
      authService.setTokens(createMockJWT({}), 'refresh_token');

      const refreshError = new Error('Refresh failed');
      (mockHttp.post as ReturnType<typeof vi.fn>).mockRejectedValueOnce(refreshError);

      await authService.refresh();

      expect(authService.getLastRefreshError()).toBeInstanceOf(Error);
      expect(authService.getLastRefreshError()?.message).toBe('Refresh failed');
    });

    it('should handle non-Error refresh failures', async () => {
      authService.setTokens(createMockJWT({}), 'refresh_token');

      (mockHttp.post as ReturnType<typeof vi.fn>).mockRejectedValueOnce('string error');

      await authService.refresh();

      expect(authService.getLastRefreshError()).toBeInstanceOf(Error);
    });

    it('should clear last refresh error on successful refresh', async () => {
      authService.setTokens(createMockJWT({}), 'refresh_token');

      // First, create an error
      (mockHttp.post as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('First error'));
      await authService.refresh();
      expect(authService.getLastRefreshError()).not.toBeNull();

      // Then successful refresh
      const refreshResponse: AuthResponse = {
        accessToken: createMockJWT({}),
        refreshToken: 'new_refresh',
        expiresIn: 3600,
        party: {
          id: 'party_123',
          email: 'test@example.com',
          name: 'Test User',
          kind: 'person',
        },
      };
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: refreshResponse });

      await authService.refresh();

      expect(authService.getLastRefreshError()).toBeNull();
    });

    it('should extract expiry from token when expiresIn not provided', async () => {
      authService.setTokens(createMockJWT({}), 'refresh_token');

      const refreshResponse: AuthResponse = {
        accessToken: createMockJWT({}, 7200),
        refreshToken: 'new_refresh',
        expiresIn: 0, // Falsy
        party: {
          id: 'party_123',
          email: 'test@example.com',
          name: 'Test User',
          kind: 'person',
        },
      };
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: refreshResponse });

      const result = await authService.refresh();

      expect(result).toBe(true);
    });
  });

  describe('logout', () => {
    it('should logout and call server endpoint', async () => {
      authService.setTokens(createMockJWT({}), 'refresh_token');

      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: { success: true } });

      const result = await authService.logout();

      expect(result).toBe(true);
      expect(authService.isAuthenticated()).toBe(false);
      expect(authService.getToken()).toBeNull();
      expect(authService.getRefreshToken()).toBeNull();
      expect(mockHttp.post).toHaveBeenCalledWith(
        '/api/auth/logout',
        { refreshToken: 'refresh_token' },
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: expect.stringContaining('Bearer'),
          }),
        })
      );
    });

    it('should emit logout event', async () => {
      authService.setTokens(createMockJWT({}), 'refresh_token');
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: {} });

      const callback = vi.fn();
      authService.onAuthChange(callback);

      await authService.logout();

      expect(callback).toHaveBeenCalledWith({
        isAuthenticated: false,
        event: 'logout',
      });
    });

    it('should clear tokens even when server logout fails', async () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      authService.setTokens(createMockJWT({}), 'refresh_token');

      (mockHttp.post as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Server error'));

      const result = await authService.logout();

      expect(result).toBe(false);
      expect(authService.isAuthenticated()).toBe(false);
      expect(warnSpy).toHaveBeenCalledWith('Server-side logout failed (tokens cleared locally):', expect.any(String));

      warnSpy.mockRestore();
    });

    it('should succeed without server call when not authenticated', async () => {
      // Not logged in
      const result = await authService.logout();

      expect(result).toBe(true);
      expect(mockHttp.post).not.toHaveBeenCalled();
    });

    it('should succeed without server call when only access token exists', async () => {
      authService.setToken(createMockJWT({}));
      // No refresh token set

      const result = await authService.logout();

      expect(result).toBe(true);
      expect(mockHttp.post).not.toHaveBeenCalled();
    });
  });

  describe('token management', () => {
    describe('setToken', () => {
      it('should set access token and extract expiry', () => {
        const token = createMockJWT({ sub: 'party_123' });
        authService.setToken(token);

        expect(authService.getToken()).toBe(token);
        expect(authService.isAuthenticated()).toBe(true);
      });
    });

    describe('setRefreshToken', () => {
      it('should set refresh token', () => {
        authService.setRefreshToken('refresh_token_123');

        expect(authService.getRefreshToken()).toBe('refresh_token_123');
        expect(authService.canRefresh()).toBe(true);
      });
    });

    describe('setTokens', () => {
      it('should set both access and refresh tokens', () => {
        const token = createMockJWT({});
        authService.setTokens(token, 'refresh_token_456');

        expect(authService.getToken()).toBe(token);
        expect(authService.getRefreshToken()).toBe('refresh_token_456');
        expect(authService.isAuthenticated()).toBe(true);
        expect(authService.canRefresh()).toBe(true);
      });
    });
  });

  describe('isTokenExpired', () => {
    it('should return true when no token set', () => {
      expect(authService.isTokenExpired()).toBe(true);
    });

    it('should return false when token is not expired', () => {
      const token = createMockJWT({}, 3600); // Expires in 1 hour
      authService.setToken(token);

      expect(authService.isTokenExpired()).toBe(false);
    });

    it('should return true when token is expired', () => {
      const token = createMockJWT({}, -60); // Expired 1 minute ago
      authService.setToken(token);

      expect(authService.isTokenExpired()).toBe(true);
    });

    it('should use buffer for expiry check', () => {
      const token = createMockJWT({}, 20); // Expires in 20 seconds
      authService.setToken(token);

      // With 30 second buffer (default), should be considered expired
      expect(authService.isTokenExpired(30)).toBe(true);

      // With 10 second buffer, should not be expired
      expect(authService.isTokenExpired(10)).toBe(false);
    });
  });

  describe('JWT decoding and validation', () => {
    it('should handle invalid JWT format', () => {
      authService.setToken('not-a-valid-jwt');

      // Should not crash but expiry won't be set
      expect(authService.isTokenExpired()).toBe(true);
    });

    it('should handle JWT with wrong number of parts', () => {
      authService.setToken('only.two');

      expect(authService.isTokenExpired()).toBe(true);
    });

    it('should warn when issuer mismatches', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const token = createMockJWT({ iss: 'wrong-issuer' });
      authService.setToken(token);

      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('JWT issuer mismatch'));

      warnSpy.mockRestore();
    });

    it('should warn when audience mismatches', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const token = createMockJWT({ aud: 'wrong-audience' });
      authService.setToken(token);

      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('JWT audience mismatch'));

      warnSpy.mockRestore();
    });

    it('should handle JWT without exp claim', () => {
      // Create token without exp
      const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'party_123' })).toString('base64url');
      const signature = Buffer.from('sig').toString('base64url');
      const token = `${header}.${payload}.${signature}`;

      authService.setToken(token);

      expect(authService.isTokenExpired()).toBe(true);
    });
  });

  describe('auth state callbacks', () => {
    it('should register callback with onAuthChange', () => {
      const callback = vi.fn();
      authService.onAuthChange(callback);

      // Trigger an auth event
      authService.setTokens(createMockJWT({}), 'refresh');
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: {} });

      // Note: setToken doesn't emit, but logout does
      // We'll trigger via logout
    });

    it('should unregister callback with offAuthChange', async () => {
      const callback = vi.fn();
      authService.onAuthChange(callback);
      authService.offAuthChange(callback);

      authService.setTokens(createMockJWT({}), 'refresh');
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: {} });
      await authService.logout();

      expect(callback).not.toHaveBeenCalled();
    });

    it('should handle callback errors gracefully', async () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const errorCallback = vi.fn().mockImplementation(() => {
        throw new Error('Callback error');
      });
      authService.onAuthChange(errorCallback);

      authService.setTokens(createMockJWT({}), 'refresh');
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: {} });
      await authService.logout();

      expect(errorSpy).toHaveBeenCalledWith('Auth state callback error:', expect.any(Error));

      errorSpy.mockRestore();
    });

    it('should call multiple callbacks', async () => {
      const callback1 = vi.fn();
      const callback2 = vi.fn();

      authService.onAuthChange(callback1);
      authService.onAuthChange(callback2);

      authService.setTokens(createMockJWT({}), 'refresh');
      (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: {} });
      await authService.logout();

      expect(callback1).toHaveBeenCalled();
      expect(callback2).toHaveBeenCalled();
    });
  });

  describe('getters', () => {
    it('getToken should return null when not authenticated', () => {
      expect(authService.getToken()).toBeNull();
    });

    it('getRefreshToken should return null when not set', () => {
      expect(authService.getRefreshToken()).toBeNull();
    });

    it('isAuthenticated should return false when not authenticated', () => {
      expect(authService.isAuthenticated()).toBe(false);
    });

    it('canRefresh should return false when no refresh token', () => {
      expect(authService.canRefresh()).toBe(false);
    });

    it('getLastRefreshError should return null initially', () => {
      expect(authService.getLastRefreshError()).toBeNull();
    });
  });
});
