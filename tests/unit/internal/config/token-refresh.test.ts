import { describe, it, expect, vi } from 'vitest';
import axios, { AxiosError, type AxiosAdapter, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import {
  addTokenRefreshInterceptor,
  createTokenRefresher,
  type TokenRefresher,
} from '../../../../src/internal/config/token-refresh.js';

interface FakeAuth extends TokenRefresher {
  token: string | null;
  refresh: ReturnType<typeof vi.fn<() => Promise<boolean>>>;
}

function fakeAuth(options: { refreshTo?: string | null; canRefresh?: boolean; refreshError?: Error } = {}): FakeAuth {
  const auth: FakeAuth = {
    token: 'expired-token',
    refresh: vi.fn<() => Promise<boolean>>(async () => {
      if (options.refreshTo === null) return false;
      auth.token = options.refreshTo ?? 'fresh-token';
      return true;
    }),
    canRefresh: () => options.canRefresh ?? true,
    getToken: () => auth.token,
    getLastRefreshError: () => options.refreshError ?? null,
  };
  return auth;
}

function respond(config: InternalAxiosRequestConfig, status: number, data: unknown = {}): Promise<AxiosResponse> {
  const response: AxiosResponse = { data, status, statusText: String(status), headers: {}, config };
  if (status >= 400) {
    return Promise.reject(new AxiosError(`Request failed with status code ${status}`, String(status), config, undefined, response));
  }
  return Promise.resolve(response);
}

/** Accepts only the given token; records the Authorization header and body of every request. */
function apiAccepting(validToken: string): { adapter: AxiosAdapter; seen: Array<{ auth: unknown; body: unknown }> } {
  const seen: Array<{ auth: unknown; body: unknown }> = [];
  const adapter: AxiosAdapter = async (config) => {
    const auth = config.headers.Authorization;
    seen.push({ auth, body: config.data });
    return respond(config, auth === `Bearer ${validToken}` ? 200 : 401, { ok: true });
  };
  return { adapter, seen };
}

function clientFor(auth: FakeAuth, adapter: AxiosAdapter, refresher = createTokenRefresher(auth)) {
  const instance = axios.create({ baseURL: 'https://api.example.com', adapter });
  instance.interceptors.request.use((config) => {
    if (auth.token) config.headers.Authorization = `Bearer ${auth.token}`;
    return config;
  });
  addTokenRefreshInterceptor(instance, refresher);
  return instance;
}

describe('token refresh interceptor', () => {
  describe('happy path', () => {
    it('refreshes on a 401 and retries the request with the new token', async () => {
      const auth = fakeAuth();
      const { adapter, seen } = apiAccepting('fresh-token');

      const response = await clientFor(auth, adapter).get('/api/capsas');

      expect(response.status).toBe(200);
      expect(auth.refresh).toHaveBeenCalledTimes(1);
      expect(seen.map(s => s.auth)).toEqual(['Bearer expired-token', 'Bearer fresh-token']);
    });

    it('resends the same body when retrying a POST', async () => {
      const auth = fakeAuth();
      const { adapter, seen } = apiAccepting('fresh-token');

      await clientFor(auth, adapter).post('/api/party/keys', { ids: ['party_1'] });

      expect(seen).toHaveLength(2);
      expect(seen[1]!.body).toBe(seen[0]!.body);
      expect(JSON.parse(seen[1]!.body as string)).toEqual({ ids: ['party_1'] });
    });

    it('does not refresh when the request succeeds', async () => {
      const auth = fakeAuth();
      auth.token = 'fresh-token';
      const { adapter } = apiAccepting('fresh-token');

      await clientFor(auth, adapter).get('/api/capsas');

      expect(auth.refresh).not.toHaveBeenCalled();
    });
  });

  describe('errors', () => {
    it('rejects with the refresh error when the refresh fails', async () => {
      const refreshError = new Error('Invalid or expired refresh token');
      const auth = fakeAuth({ refreshTo: null, refreshError });
      const { adapter, seen } = apiAccepting('fresh-token');

      await expect(clientFor(auth, adapter).get('/api/capsas')).rejects.toBe(refreshError);
      expect(seen).toHaveLength(1);
    });

    it('rejects with the original 401 when the refresh fails without an error', async () => {
      const auth = fakeAuth({ refreshTo: null });
      const { adapter } = apiAccepting('fresh-token');

      await expect(clientFor(auth, adapter).get('/api/capsas')).rejects.toMatchObject({ response: { status: 401 } });
    });

    it('does not refresh without a refresh token', async () => {
      const auth = fakeAuth({ canRefresh: false });
      const { adapter, seen } = apiAccepting('fresh-token');

      await expect(clientFor(auth, adapter).get('/api/capsas')).rejects.toMatchObject({ response: { status: 401 } });
      expect(auth.refresh).not.toHaveBeenCalled();
      expect(seen).toHaveLength(1);
    });

    it('passes other error statuses through without refreshing', async () => {
      const auth = fakeAuth();
      const adapter: AxiosAdapter = (config) => respond(config, 403);

      await expect(clientFor(auth, adapter).get('/api/capsas')).rejects.toMatchObject({ response: { status: 403 } });
      expect(auth.refresh).not.toHaveBeenCalled();
    });

    it('wraps a non-Error rejection in an Error', async () => {
      const auth = fakeAuth();
      const adapter: AxiosAdapter = () => Promise.reject('socket closed');

      await expect(clientFor(auth, adapter).get('/api/capsas')).rejects.toThrow('socket closed');
    });
  });

  describe('edge cases', () => {
    it('shares one refresh between concurrent 401s', async () => {
      const auth = fakeAuth();
      let releaseRefresh!: () => void;
      auth.refresh.mockImplementation(() => new Promise<boolean>((resolve) => {
        releaseRefresh = () => { auth.token = 'fresh-token'; resolve(true); };
      }));
      const { adapter } = apiAccepting('fresh-token');
      const client = clientFor(auth, adapter);

      const calls = Promise.all([client.get('/a'), client.get('/b'), client.get('/c')]);
      await vi.waitFor(() => expect(auth.refresh).toHaveBeenCalled());
      releaseRefresh();
      const responses = await calls;

      expect(responses.map(r => r.status)).toEqual([200, 200, 200]);
      expect(auth.refresh).toHaveBeenCalledTimes(1);
    });

    it('shares one refresh between separate clients using the same refresher', async () => {
      const auth = fakeAuth();
      let releaseRefresh!: () => void;
      auth.refresh.mockImplementation(() => new Promise<boolean>((resolve) => {
        releaseRefresh = () => { auth.token = 'fresh-token'; resolve(true); };
      }));
      const refresher = createTokenRefresher(auth);
      const { adapter, seen } = apiAccepting('fresh-token');

      const calls = Promise.all([
        clientFor(auth, adapter, refresher).get('/api/capsas'),
        clientFor(auth, adapter, refresher).post('/api/party/keys', {}),
      ]);
      await vi.waitFor(() => expect(seen).toHaveLength(2));
      releaseRefresh();
      const responses = await calls;

      expect(responses.map(r => r.status)).toEqual([200, 200]);
      expect(auth.refresh).toHaveBeenCalledTimes(1);
    });

    it('does not refresh again when the retried request is still rejected', async () => {
      const auth = fakeAuth();
      const { adapter, seen } = apiAccepting('a-token-the-api-never-accepts');

      await expect(clientFor(auth, adapter).get('/api/capsas')).rejects.toMatchObject({ response: { status: 401 } });
      expect(auth.refresh).toHaveBeenCalledTimes(1);
      expect(seen).toHaveLength(2);
    });

    it('refreshes again for a later expiry once the earlier refresh has settled', async () => {
      const auth = fakeAuth();
      const { adapter } = apiAccepting('fresh-token');
      const client = clientFor(auth, adapter);

      await client.get('/api/capsas');
      auth.token = 'expired-again';
      await client.get('/api/capsas');

      expect(auth.refresh).toHaveBeenCalledTimes(2);
    });

    it('allows a new refresh after a failed one', async () => {
      const auth = fakeAuth();
      auth.refresh.mockResolvedValueOnce(false);
      const { adapter } = apiAccepting('fresh-token');
      const client = clientFor(auth, adapter);

      await expect(client.get('/api/capsas')).rejects.toMatchObject({ response: { status: 401 } });
      await expect(client.get('/api/capsas')).resolves.toMatchObject({ status: 200 });
      expect(auth.refresh).toHaveBeenCalledTimes(2);
    });
  });
});
