import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios, { AxiosError, type AxiosAdapter, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { CapsaraClient } from '../../../src/client/capsara-client.js';
import { KeyManager } from '../../../src/internal/services/key-service.js';
import { AccountClient } from '../../../src/internal/services/account-service.js';
import { createTokenRefresher, type TokenRefresher } from '../../../src/internal/config/token-refresh.js';

const BASE_URL = 'https://api.example.com';
const PARTY_KEY = { id: 'party_1', publicKey: 'PEM', fingerprint: 'fp_1' };

function respond(config: InternalAxiosRequestConfig, status: number, data: unknown = {}): Promise<AxiosResponse> {
  const response: AxiosResponse = { data, status, statusText: String(status), headers: {}, config };
  if (status >= 400) {
    return Promise.reject(new AxiosError(`Request failed with status code ${status}`, String(status), config, undefined, response));
  }
  return Promise.resolve(response);
}

/** Fake API: login issues an expired token, refresh issues a fresh one, everything else needs the fresh one. */
function fakeApi(options: { holdRefresh?: boolean } = {}) {
  const calls: Array<{ url: string; auth: unknown }> = [];
  let refreshCount = 0;
  let releaseRefresh: () => void = () => {};
  const refreshGate = options.holdRefresh
    ? new Promise<void>((resolve) => { releaseRefresh = resolve; })
    : Promise.resolve();

  const adapter: AxiosAdapter = async (config) => {
    const url = config.url ?? '';
    const auth = config.headers.Authorization;
    calls.push({ url, auth });

    if (url === '/api/auth/login') {
      return respond(config, 200, { party: { id: 'party_self' }, accessToken: 'expired-token', refreshToken: 'refresh-1', expiresIn: 900 });
    }
    if (url === '/api/auth/refresh') {
      refreshCount++;
      await refreshGate;
      return respond(config, 200, { accessToken: 'fresh-token', refreshToken: 'refresh-2', expiresIn: 900 });
    }
    if (auth !== 'Bearer fresh-token') {
      return respond(config, 401, { error: { code: 'UNAUTHORIZED', message: 'Token expired' } });
    }
    if (url === '/api/party/keys') {
      return respond(config, 200, { parties: [PARTY_KEY] });
    }
    if (url === '/api/account/key') {
      return respond(config, 200, { publicKey: 'PEM', publicKeyFingerprint: 'fp_self' });
    }
    if (url === '/api/capsas') {
      return respond(config, 200, { capsas: [{ id: 'capsa_1' }], pagination: { limit: 20, hasMore: false } });
    }
    return respond(config, 404);
  };

  return {
    adapter,
    calls,
    releaseRefresh: () => releaseRefresh(),
    get refreshCount() { return refreshCount; },
  };
}

function stubRefresher(): { refresher: TokenRefresher; auth: { token: string; refresh: ReturnType<typeof vi.fn<() => Promise<boolean>>> } } {
  const auth = {
    token: 'expired-token',
    refresh: vi.fn<() => Promise<boolean>>(async () => {
      auth.token = 'fresh-token';
      return true;
    }),
  };
  const refresher = createTokenRefresher({
    refresh: () => auth.refresh(),
    canRefresh: () => true,
    getToken: () => auth.token,
    getLastRefreshError: () => null,
  });
  return { refresher, auth };
}

describe('token refresh wiring', () => {
  let originalAdapter: typeof axios.defaults.adapter;

  beforeEach(() => {
    originalAdapter = axios.defaults.adapter;
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    axios.defaults.adapter = originalAdapter;
    vi.restoreAllMocks();
  });

  describe('KeyManager', () => {
    it('refreshes once on a 401 and the retried key lookup succeeds', async () => {
      const api = fakeApi();
      axios.defaults.adapter = api.adapter;
      const { refresher, auth } = stubRefresher();
      const keyManager = new KeyManager(BASE_URL, () => auth.token, { tokenRefresher: refresher });

      const keys = await keyManager.fetchPartyKeys(['party_1']);

      expect(keys).toEqual([PARTY_KEY]);
      expect(auth.refresh).toHaveBeenCalledTimes(1);
      expect(api.calls.map(c => c.auth)).toEqual(['Bearer expired-token', 'Bearer fresh-token']);
    });

    it('surfaces the 401 when no refresher is configured', async () => {
      const api = fakeApi();
      axios.defaults.adapter = api.adapter;
      const keyManager = new KeyManager(BASE_URL, () => 'expired-token');

      await expect(keyManager.fetchPartyKeys(['party_1'])).rejects.toMatchObject({ response: { status: 401 } });
      expect(api.calls).toHaveLength(1);
    });
  });

  describe('AccountClient', () => {
    it('refreshes once on a 401 and the retried call succeeds', async () => {
      const api = fakeApi();
      axios.defaults.adapter = api.adapter;
      const { refresher, auth } = stubRefresher();
      const account = new AccountClient(BASE_URL, () => auth.token, undefined, undefined, refresher);

      const key = await account.getCurrentPublicKey();

      expect(key).toMatchObject({ publicKey: 'PEM', keyFingerprint: 'fp_self' });
      expect(auth.refresh).toHaveBeenCalledTimes(1);
      expect(api.calls.map(c => c.auth)).toEqual(['Bearer expired-token', 'Bearer fresh-token']);
    });

    it('does not refresh when no refresher is configured', async () => {
      const api = fakeApi();
      axios.defaults.adapter = api.adapter;
      const account = new AccountClient(BASE_URL, () => 'expired-token');

      await expect(account.getCurrentPublicKey()).rejects.toMatchObject({ code: 'UNAUTHORIZED', statusCode: 401 });
      expect(api.calls).toHaveLength(1);
    });
  });

  describe('CapsaraClient', () => {
    async function loggedInClient(api: ReturnType<typeof fakeApi>): Promise<CapsaraClient> {
      axios.defaults.adapter = api.adapter;
      const client = new CapsaraClient(BASE_URL, { retry: { maxRetries: 0 } });
      await client.login({ partyId: 'party_self', password: 'pw' });
      return client;
    }

    it('refreshes for account calls made through the client', async () => {
      const api = fakeApi();
      const client = await loggedInClient(api);

      await expect(client.getCurrentPublicKey()).resolves.toMatchObject({ publicKey: 'PEM' });
      expect(api.refreshCount).toBe(1);
    });

    it('shares one refresh between concurrent 401s on the main client, key lookups and account calls', async () => {
      const api = fakeApi({ holdRefresh: true });
      const client = await loggedInClient(api);
      const keyManager = (client as unknown as { keyManager: KeyManager }).keyManager;

      const calls = Promise.all([
        client.listCapsas(),
        keyManager.fetchPartyKeys(['party_1']),
        client.getCurrentPublicKey(),
      ]);
      await vi.waitFor(() => expect(api.refreshCount).toBe(1));
      await vi.waitFor(() => expect(api.calls.filter(c => c.auth === 'Bearer expired-token')).toHaveLength(3));
      api.releaseRefresh();
      const [list, partyKey, ownKey] = await calls;

      expect(list.capsas).toEqual([{ id: 'capsa_1' }]);
      expect(partyKey).toEqual([PARTY_KEY]);
      expect(ownKey).toMatchObject({ publicKey: 'PEM' });
      expect(api.refreshCount).toBe(1);
    });
  });
});
