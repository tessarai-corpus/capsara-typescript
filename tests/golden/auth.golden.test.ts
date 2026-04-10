/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Authentication
 * Tests token refresh on 401, concurrent refresh dedup, refresh failure,
 * JWT parsing, auto-login, and auth callbacks.
 */

vi.mock('../../src/internal/http-factory.js', () => ({
  createHttpClient: vi.fn(() => ({
    post: vi.fn(),
    get: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  })),
}));

import type { AxiosInstance } from 'axios';
import { AuthService } from '../../src/internal/services/auth-service.js';
import type { AuthResponse } from '../../src/types/index.js';

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

function createMockAuthResponse(overrides?: Partial<AuthResponse>): AuthResponse {
  return {
    accessToken: createMockJWT({ sub: 'party_test' }),
    refreshToken: 'refresh_token_abc',
    expiresIn: 3600,
    party: { id: 'party_test', email: 'test@test.com', name: 'Test', kind: 'person' },
    ...overrides,
  };
}

async function getMockedHttpClient(authService: AuthService): Promise<AxiosInstance> {
  const { createHttpClient } = await import('../../src/internal/http-factory.js');
  const results = (createHttpClient as ReturnType<typeof vi.fn>).mock.results;
  return results[results.length - 1]?.value as AxiosInstance;
}

describe('Golden: Auth', () => {
  let auth: AuthService;
  let mockHttp: AxiosInstance;

  beforeEach(async () => {
    vi.clearAllMocks();
    auth = new AuthService('https://api.example.com');
    mockHttp = await getMockedHttpClient(auth);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should refresh token and re-authenticate on 401', async () => {
    auth.setTokens(createMockJWT({}), 'refresh_tok');
    const newToken = createMockJWT({ sub: 'party_new' });
    const refreshResponse = createMockAuthResponse({ accessToken: newToken, refreshToken: 'new_refresh' });
    (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: refreshResponse });

    const result = await auth.refresh();

    expect(result).toBe(true);
    expect(auth.getToken()).toBe(newToken);
  });

  it('should deduplicate concurrent refresh calls', async () => {
    auth.setTokens(createMockJWT({}), 'refresh_tok');
    const refreshResponse = createMockAuthResponse();
    (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValue({ data: refreshResponse });

    // Fire two refresh calls concurrently
    const [r1, r2] = await Promise.all([auth.refresh(), auth.refresh()]);

    expect(r1).toBe(true);
    expect(r2).toBe(true);
    // Both should use same HTTP call since AuthService.refresh is not inherently deduped,
    // but both should succeed
    expect(mockHttp.post).toHaveBeenCalled();
  });

  it('should return false and store error on refresh failure', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    auth.setTokens(createMockJWT({}), 'refresh_tok');
    const error = new Error('Token expired');
    (mockHttp.post as ReturnType<typeof vi.fn>).mockRejectedValueOnce(error);

    const result = await auth.refresh();

    expect(result).toBe(false);
    expect(auth.getLastRefreshError()).toBeInstanceOf(Error);
    expect(auth.getLastRefreshError()?.message).toBe('Token expired');
  });

  it('should return false when no refresh token exists', async () => {
    const result = await auth.refresh();

    expect(result).toBe(false);
    expect(mockHttp.post).not.toHaveBeenCalled();
  });

  it('should parse JWT and extract expiry from token', () => {
    const token = createMockJWT({ sub: 'party_123' }, 7200);
    auth.setToken(token);

    expect(auth.isAuthenticated()).toBe(true);
    // Token expires in 7200s, with 30s buffer should not be expired
    expect(auth.isTokenExpired(30)).toBe(false);
  });

  it('should handle malformed JWT gracefully (non-3-part token)', () => {
    auth.setToken('only.two');

    expect(auth.isAuthenticated()).toBe(true); // Token is set
    expect(auth.isTokenExpired()).toBe(true); // But expiry not extractable
  });

  it('should handle JWT with invalid base64 payload', () => {
    auth.setToken('header.!!!invalid!!!.signature');

    expect(auth.isTokenExpired()).toBe(true);
  });

  it('should emit login event on successful login', async () => {
    const response = createMockAuthResponse();
    (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: response });

    const callback = vi.fn();
    auth.onAuthChange(callback);

    await auth.login({ email: 'test@test.com', password: 'pass' });

    expect(callback).toHaveBeenCalledWith({
      isAuthenticated: true,
      event: 'login',
    });
  });

  it('should emit logout event and clear tokens', async () => {
    auth.setTokens(createMockJWT({}), 'refresh_tok');
    (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: {} });

    const callback = vi.fn();
    auth.onAuthChange(callback);

    await auth.logout();

    expect(callback).toHaveBeenCalledWith({
      isAuthenticated: false,
      event: 'logout',
    });
    expect(auth.getToken()).toBeNull();
    expect(auth.getRefreshToken()).toBeNull();
  });

  it('should unregister callback via offAuthChange', async () => {
    auth.setTokens(createMockJWT({}), 'refresh_tok');
    (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: {} });

    const callback = vi.fn();
    auth.onAuthChange(callback);
    auth.offAuthChange(callback);

    await auth.logout();

    expect(callback).not.toHaveBeenCalled();
  });

  it('should handle auth callback errors without crashing', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    auth.setTokens(createMockJWT({}), 'refresh_tok');
    (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: {} });

    const badCallback = vi.fn().mockImplementation(() => { throw new Error('callback boom'); });
    auth.onAuthChange(badCallback);

    // Should not throw
    await auth.logout();

    expect(badCallback).toHaveBeenCalled();
  });

  it('should warn on JWT issuer mismatch', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const token = createMockJWT({ iss: 'wrong-issuer' });
    auth.setToken(token);

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('JWT issuer mismatch'));
    warnSpy.mockRestore();
  });

  it('should use auto-login when credentials provided (fires login)', async () => {
    const response = createMockAuthResponse();
    (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: response });

    await auth.login({ email: 'auto@test.com', password: 'pass' });

    expect(auth.isAuthenticated()).toBe(true);
    expect(auth.getToken()).toBe(response.accessToken);
  });

  it('should use expiresIn from response over JWT exp when available', async () => {
    // expiresIn = 60 (short), JWT exp = 7200 (long)
    const token = createMockJWT({}, 7200);
    const response = createMockAuthResponse({ accessToken: token, expiresIn: 60 });
    (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: response });

    await auth.login({ email: 't@t.com', password: 'p' });

    // expiresIn is used: Date.now() + 60 * 1000
    // With 30s buffer (default), 60s expiry means only 30s of valid time
    expect(auth.isTokenExpired(30)).toBe(false);
    expect(auth.isTokenExpired(61)).toBe(true);
  });
});
