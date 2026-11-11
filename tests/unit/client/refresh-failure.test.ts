import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios, { AxiosError, type AxiosAdapter, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { CapsaraClient } from '../../../src/client/capsara-client.js';
import { CapsaraAuthError } from '../../../src/errors/auth-error.js';
import { CapsaraCapsaError } from '../../../src/errors/capsa-error.js';
import { CapsaraAuditError } from '../../../src/errors/audit-error.js';
import { CapsaraAccountError } from '../../../src/errors/account-error.js';

const BASE_URL = 'https://api.example.com';

type RefreshMode = 'reject' | 'network' | 'ok';

function respond(config: InternalAxiosRequestConfig, status: number, data: unknown = {}): Promise<AxiosResponse> {
  const response: AxiosResponse = { data, status, statusText: String(status), headers: {}, config };
  if (status >= 400) {
    return Promise.reject(new AxiosError(`Request failed with status code ${status}`, String(status), config, {}, response));
  }
  return Promise.resolve(response);
}

function fakeApi() {
  const state = {
    refreshMode: 'reject' as RefreshMode,
    refreshGate: Promise.resolve(),
    refreshCount: 0,
  };

  const adapter: AxiosAdapter = async (config) => {
    const url = config.url ?? '';
    if (url === '/api/auth/login') {
      return respond(config, 200, { party: { id: 'party_self' }, accessToken: 'expired-token', refreshToken: 'refresh-1', expiresIn: 900 });
    }
    if (url === '/api/auth/logout') {
      return respond(config, 200, { success: true });
    }
    if (url === '/api/auth/refresh') {
      state.refreshCount++;
      await state.refreshGate;
      if (state.refreshMode === 'network') {
        throw new AxiosError('connect ECONNREFUSED', 'ECONNREFUSED', config, {});
      }
      if (state.refreshMode === 'reject') {
        return respond(config, 401, { error: { code: 'INVALID_REFRESH_TOKEN', message: 'Refresh token revoked' } });
      }
      return respond(config, 200, { accessToken: 'fresh-token', refreshToken: 'refresh-2', expiresIn: 900 });
    }
    return respond(config, 401, { error: { code: 'UNAUTHORIZED', message: 'Token expired' } });
  };

  return { adapter, state };
}

describe('refresh failure during an API call', () => {
  let originalAdapter: typeof axios.defaults.adapter;
  let api: ReturnType<typeof fakeApi>;
  let client: CapsaraClient;

  beforeEach(async () => {
    originalAdapter = axios.defaults.adapter;
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    api = fakeApi();
    axios.defaults.adapter = api.adapter;
    client = new CapsaraClient(BASE_URL, { retry: { maxRetries: 0 } });
    await client.login({ partyId: 'party_self', password: 'pw' });
  });

  afterEach(() => {
    axios.defaults.adapter = originalAdapter;
    vi.restoreAllMocks();
  });

  it('surfaces the refresh rejection as an auth error on capsa, audit and account calls', async () => {
    const calls = [
      client.getCapsa('capsa_1', { decrypt: false }),
      client.listCapsas(),
      client.getAuditEntries('capsa_1'),
      client.getCurrentPublicKey(),
    ];

    for (const call of calls) {
      const error = await call.catch((e: unknown) => e);
      expect(error).toBeInstanceOf(CapsaraAuthError);
      expect(error).not.toBeInstanceOf(CapsaraCapsaError);
      expect(error).not.toBeInstanceOf(CapsaraAuditError);
      expect(error).not.toBeInstanceOf(CapsaraAccountError);
      expect(error).toMatchObject({ code: 'INVALID_REFRESH_TOKEN', statusCode: 401, message: 'Refresh token revoked' });
    }
  });

  it('surfaces an unreachable refresh endpoint as an auth NETWORK_ERROR', async () => {
    api.state.refreshMode = 'network';

    const error = await client.getCapsa('capsa_1', { decrypt: false }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(CapsaraAuthError);
    expect(error).toMatchObject({ code: 'NETWORK_ERROR', statusCode: 0, details: { originalError: 'connect ECONNREFUSED' } });
  });

  it('surfaces the original 401 when logout wins the race against a successful refresh', async () => {
    let release: () => void = () => {};
    api.state.refreshMode = 'ok';
    api.state.refreshGate = new Promise<void>((resolve) => { release = resolve; });

    const pending = client.getCapsa('capsa_1', { decrypt: false }).catch((e: unknown) => e);
    await vi.waitFor(() => expect(api.state.refreshCount).toBe(1));
    await client.logout();
    release();
    const error = await pending;

    expect(error).toBeInstanceOf(CapsaraCapsaError);
    expect(error).toMatchObject({ code: 'UNAUTHORIZED', statusCode: 401 });
  });

  it('surfaces the original 401, not a stale earlier refresh error, when logout wins the race against a failing refresh', async () => {
    await client.listCapsas().catch(() => undefined);
    await client.logout();
    await client.login({ partyId: 'party_self', password: 'pw' });

    let release: () => void = () => {};
    api.state.refreshMode = 'network';
    api.state.refreshGate = new Promise<void>((resolve) => { release = resolve; });

    const pending = client.getCapsa('capsa_1', { decrypt: false }).catch((e: unknown) => e);
    await vi.waitFor(() => expect(api.state.refreshCount).toBe(2));
    await client.logout();
    release();
    const error = await pending;

    expect(error).toBeInstanceOf(CapsaraCapsaError);
    expect(error).toMatchObject({ code: 'UNAUTHORIZED', statusCode: 401 });
  });
});
