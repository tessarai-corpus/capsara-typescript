import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import axios, { type AxiosAdapter, type AxiosResponse } from 'axios';
import { CapsaraClient } from '../../../src/client/capsara-client.js';
import { KeyManager } from '../../../src/internal/services/key-service.js';
import { SDK_VERSION } from '../../../src/internal/version.js';

const BASE_URL = 'https://api.example.com';

describe('custom user agent on every API client', () => {
  let originalAdapter: typeof axios.defaults.adapter;
  const seen = new Map<string, unknown>();

  beforeEach(() => {
    originalAdapter = axios.defaults.adapter;
    seen.clear();
    const adapter: AxiosAdapter = async (config) => {
      seen.set(config.url ?? '', config.headers['User-Agent']);
      const data = config.url === '/api/party/keys' ? { parties: [] } : config.url === '/api/limits' ? {} : { publicKey: null };
      const response: AxiosResponse = { data, status: 200, statusText: 'OK', headers: {}, config };
      return response;
    };
    axios.defaults.adapter = adapter;
  });

  afterEach(() => {
    axios.defaults.adapter = originalAdapter;
  });

  it('appends the custom user agent on party keys, account and limits requests', async () => {
    const client = new CapsaraClient(BASE_URL, { userAgent: 'MyApp/1.0', accessToken: 'token' });
    const keyManager = (client as unknown as { keyManager: KeyManager }).keyManager;

    await keyManager.fetchPartyKeys(['party_1']);
    await client.getCurrentPublicKey();
    await client.getLimits();

    for (const url of ['/api/party/keys', '/api/account/key', '/api/limits']) {
      expect(seen.get(url)).toMatch(new RegExp(`^Capsara-SDK-typescript/${SDK_VERSION.replace(/\./g, '\\.')} .* MyApp/1\\.0$`));
    }
  });

  it('sends the default user agent when none is configured', async () => {
    const client = new CapsaraClient(BASE_URL, { accessToken: 'token' });

    await client.getCurrentPublicKey();

    expect(seen.get('/api/account/key')).toMatch(/^Capsara-SDK-typescript\/\S+ \(Node\.js [^)]+\)$/);
  });
});
