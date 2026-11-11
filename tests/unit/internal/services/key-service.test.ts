/**
 * Tests for key-service.ts - Party key management
 * @file tests/unit/internal/services/key-service.test.ts
 */

import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import type { AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import type { PartyKey } from '../../../../src/types/index.js';

// Use vi.hoisted for mock functions
const { mockAxiosCreate, mockConfigureRetryInterceptor } = vi.hoisted(() => ({
  mockAxiosCreate: vi.fn(),
  mockConfigureRetryInterceptor: vi.fn(),
}));

// Mock axios
vi.mock('axios', () => ({
  default: {
    create: mockAxiosCreate,
  },
}));

// Mock http-client
vi.mock('../../../../src/internal/config/http-client.js', () => ({
  createAxiosConfig: vi.fn().mockReturnValue({
    baseURL: 'https://api.example.com',
    timeout: 60000,
    headers: {
      'Content-Type': 'application/json',
    },
  }),
  configureRetryInterceptor: mockConfigureRetryInterceptor,
  DEFAULT_TIMEOUT_CONFIG: {
    apiTimeout: 60000,
    uploadTimeout: 120000,
    downloadTimeout: 30000,
    requestTimeout: 30000,
    maxSockets: 50,
    keepAlive: true,
  },
}));

import { KeyManager, type KeyManagerOptions } from '../../../../src/internal/services/key-service.js';
import { CapsaraError } from '../../../../src/errors/capsara-error.js';
import { CapsaraAuthError } from '../../../../src/errors/auth-error.js';

// Helper to create mock axios instance with request interceptor support
function createMockAxiosInstance(): AxiosInstance & {
  interceptorCallbacks: Array<(config: InternalAxiosRequestConfig) => InternalAxiosRequestConfig>;
} {
  const interceptorCallbacks: Array<(config: InternalAxiosRequestConfig) => InternalAxiosRequestConfig> = [];

  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    patch: vi.fn(),
    request: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    defaults: {},
    interceptors: {
      request: {
        use: vi.fn((callback: (config: InternalAxiosRequestConfig) => InternalAxiosRequestConfig) => {
          interceptorCallbacks.push(callback);
          return interceptorCallbacks.length - 1;
        }),
        eject: vi.fn(),
        clear: vi.fn(),
      },
      response: { use: vi.fn(), eject: vi.fn(), clear: vi.fn() },
    },
    interceptorCallbacks,
  } as unknown as AxiosInstance & {
    interceptorCallbacks: Array<(config: InternalAxiosRequestConfig) => InternalAxiosRequestConfig>;
  };
}

describe('KeyManager', () => {
  let mockAxios: ReturnType<typeof createMockAxiosInstance>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockAxios = createMockAxiosInstance();
    mockAxiosCreate.mockReturnValue(mockAxios);
  });

  describe('constructor', () => {
    it('should create axios instance with base URL', () => {
      const getToken = vi.fn().mockReturnValue('test-token');

      new KeyManager('https://api.example.com', getToken);

      expect(mockAxiosCreate).toHaveBeenCalled();
      expect(mockConfigureRetryInterceptor).toHaveBeenCalled();
    });

    it('should accept custom timeout options', () => {
      const getToken = vi.fn().mockReturnValue(null);
      const options: KeyManagerOptions = {
        timeout: {
          apiTimeout: 30000,
        },
      };

      new KeyManager('https://api.example.com', getToken, options);

      expect(mockAxiosCreate).toHaveBeenCalled();
    });

    it('should accept custom retry options', () => {
      const getToken = vi.fn().mockReturnValue(null);
      const options: KeyManagerOptions = {
        retry: {
          maxRetries: 5,
          baseDelay: 2000,
        },
      };

      new KeyManager('https://api.example.com', getToken, options);

      expect(mockConfigureRetryInterceptor).toHaveBeenCalledWith(
        mockAxios,
        expect.objectContaining({ maxRetries: 5, baseDelay: 2000 })
      );
    });

    it('should configure auth interceptor', () => {
      const getToken = vi.fn().mockReturnValue('test-token');

      new KeyManager('https://api.example.com', getToken);

      expect(mockAxios.interceptors.request.use).toHaveBeenCalled();
    });

    it('should add bearer token when available', () => {
      const getToken = vi.fn().mockReturnValue('my-auth-token');

      new KeyManager('https://api.example.com', getToken);

      // Get the interceptor callback
      const callback = mockAxios.interceptorCallbacks[0]!;
      const config = { headers: {} } as InternalAxiosRequestConfig;
      const result = callback(config);

      expect(result.headers.Authorization).toBe('Bearer my-auth-token');
    });

    it('should not add auth header when token is null', () => {
      const getToken = vi.fn().mockReturnValue(null);

      new KeyManager('https://api.example.com', getToken);

      // Get the interceptor callback
      const callback = mockAxios.interceptorCallbacks[0]!;
      const config = { headers: {} } as InternalAxiosRequestConfig;
      const result = callback(config);

      expect(result.headers.Authorization).toBeUndefined();
    });
  });

  describe('fetchPartyKeys', () => {
    it('should fetch multiple party keys', async () => {
      const partyKeys: PartyKey[] = [
        {
          id: 'party_1',
          publicKey: '-----BEGIN PUBLIC KEY-----\nKey1...\n-----END PUBLIC KEY-----',
          fingerprint: 'SHA256:key1',
        },
        {
          id: 'party_2',
          publicKey: '-----BEGIN PUBLIC KEY-----\nKey2...\n-----END PUBLIC KEY-----',
          fingerprint: 'SHA256:key2',
        },
        {
          id: 'party_3',
          publicKey: '-----BEGIN PUBLIC KEY-----\nKey3...\n-----END PUBLIC KEY-----',
          fingerprint: 'SHA256:key3',
        },
      ];

      (mockAxios.post as Mock).mockResolvedValue({
        data: { parties: partyKeys },
      });

      const getToken = vi.fn().mockReturnValue('test-token');
      const manager = new KeyManager('https://api.example.com', getToken);

      const result = await manager.fetchPartyKeys(['party_1', 'party_2', 'party_3']);

      expect(result).toEqual(partyKeys);
      expect(result).toHaveLength(3);
      expect(mockAxios.post).toHaveBeenCalledWith('/api/party/keys', {
        ids: ['party_1', 'party_2', 'party_3'],
      });
    });

    it('should return empty array when no parties found', async () => {
      (mockAxios.post as Mock).mockResolvedValue({
        data: { parties: [] },
      });

      const getToken = vi.fn().mockReturnValue('test-token');
      const manager = new KeyManager('https://api.example.com', getToken);

      const result = await manager.fetchPartyKeys(['nonexistent_1', 'nonexistent_2']);

      expect(result).toEqual([]);
    });

    it('should include delegates in response', async () => {
      const partyKeys: PartyKey[] = [
        {
          id: 'party_1',
          publicKey: '-----BEGIN PUBLIC KEY-----\nKey1...\n-----END PUBLIC KEY-----',
          fingerprint: 'SHA256:key1',
        },
        {
          id: 'delegate_of_party_1',
          publicKey: '-----BEGIN PUBLIC KEY-----\nKeyDelegate...\n-----END PUBLIC KEY-----',
          fingerprint: 'SHA256:delegate',
        },
      ];

      (mockAxios.post as Mock).mockResolvedValue({
        data: { parties: partyKeys },
      });

      const getToken = vi.fn().mockReturnValue('test-token');
      const manager = new KeyManager('https://api.example.com', getToken);

      const result = await manager.fetchPartyKeys(['party_1']);

      // fetchPartyKeys includes delegates
      expect(result).toHaveLength(2);
      expect(result[0]?.id).toBe('party_1');
      expect(result[1]?.id).toBe('delegate_of_party_1');
    });

    it('should handle large batches via POST', async () => {
      const largePartyIds = Array.from({ length: 100 }, (_, i) => `party_${i}`);
      const partyKeys: PartyKey[] = largePartyIds.map((id) => ({
        id,
        publicKey: `-----BEGIN PUBLIC KEY-----\n${id}Key\n-----END PUBLIC KEY-----`,
        fingerprint: `SHA256:${id}`,
      }));

      (mockAxios.post as Mock).mockResolvedValue({
        data: { parties: partyKeys },
      });

      const getToken = vi.fn().mockReturnValue('test-token');
      const manager = new KeyManager('https://api.example.com', getToken);

      const result = await manager.fetchPartyKeys(largePartyIds);

      expect(result).toHaveLength(100);
      expect(mockAxios.post).toHaveBeenCalledWith('/api/party/keys', {
        ids: largePartyIds,
      });
    });

    function keyFor(id: string, isDelegate?: string[]): PartyKey {
      return { id, publicKey: `pem_${id}`, fingerprint: `fp_${id}`, ...(isDelegate && { isDelegate }) };
    }

    it('sends exactly 500 ids in one request', async () => {
      const ids = Array.from({ length: 500 }, (_, i) => `party_${i}`);
      (mockAxios.post as Mock).mockResolvedValue({ data: { parties: [] } });
      const manager = new KeyManager('https://api.example.com', vi.fn().mockReturnValue('t'));

      await manager.fetchPartyKeys(ids);

      expect(mockAxios.post).toHaveBeenCalledTimes(1);
    });

    it('splits more than 500 ids into sequential requests of at most 500 and concatenates the results', async () => {
      const ids = Array.from({ length: 1201 }, (_, i) => `party_${i}`);
      (mockAxios.post as Mock).mockImplementation(async (_url: string, body: { ids: string[] }) => ({
        data: { parties: body.ids.map(id => keyFor(id)) },
      }));
      const manager = new KeyManager('https://api.example.com', vi.fn().mockReturnValue('t'));

      const result = await manager.fetchPartyKeys(ids);

      const sent = (mockAxios.post as Mock).mock.calls.map(call => (call[1] as { ids: string[] }).ids);
      expect(sent.map(chunk => chunk.length)).toEqual([500, 500, 201]);
      expect(sent.flat()).toEqual(ids);
      expect(result.map(p => p.id)).toEqual(ids);
    });

    it('drops duplicate ids before splitting', async () => {
      const ids = [...Array.from({ length: 500 }, (_, i) => `party_${i}`), 'party_0', 'party_1'];
      (mockAxios.post as Mock).mockResolvedValue({ data: { parties: [] } });
      const manager = new KeyManager('https://api.example.com', vi.fn().mockReturnValue('t'));

      await manager.fetchPartyKeys(ids);

      expect(mockAxios.post).toHaveBeenCalledTimes(1);
    });

    it('merges a party returned by several requests, combining whom it acts for', async () => {
      const ids = Array.from({ length: 501 }, (_, i) => `party_${i}`);
      (mockAxios.post as Mock)
        .mockResolvedValueOnce({ data: { parties: [keyFor('party_0'), keyFor('delegate_d', ['party_0'])] } })
        .mockResolvedValueOnce({ data: { parties: [keyFor('party_500'), keyFor('delegate_d', ['party_500'])] } });
      const manager = new KeyManager('https://api.example.com', vi.fn().mockReturnValue('t'));

      const result = await manager.fetchPartyKeys(ids);

      expect(result.filter(p => p.id === 'delegate_d')).toEqual([keyFor('delegate_d', ['party_0', 'party_500'])]);
      expect(result.map(p => p.id)).toEqual(['party_0', 'delegate_d', 'party_500']);
    });

    it('keeps the first entry for a party repeated without delegate info', async () => {
      const ids = Array.from({ length: 501 }, (_, i) => `party_${i}`);
      (mockAxios.post as Mock)
        .mockResolvedValueOnce({ data: { parties: [keyFor('shared')] } })
        .mockResolvedValueOnce({ data: { parties: [{ ...keyFor('shared'), fingerprint: 'other' }] } });
      const manager = new KeyManager('https://api.example.com', vi.fn().mockReturnValue('t'));

      const result = await manager.fetchPartyKeys(ids);

      expect(result).toEqual([keyFor('shared')]);
    });

    it('takes a boolean delegate flag from a later entry when the first has none', async () => {
      const ids = Array.from({ length: 501 }, (_, i) => `party_${i}`);
      (mockAxios.post as Mock)
        .mockResolvedValueOnce({ data: { parties: [keyFor('shared')] } })
        .mockResolvedValueOnce({ data: { parties: [{ ...keyFor('shared'), isDelegate: true }] } });
      const manager = new KeyManager('https://api.example.com', vi.fn().mockReturnValue('t'));

      const result = await manager.fetchPartyKeys(ids);

      expect(result).toEqual([{ ...keyFor('shared'), isDelegate: true }]);
    });

    it('propagates a failure of a later request', async () => {
      const ids = Array.from({ length: 501 }, (_, i) => `party_${i}`);
      (mockAxios.post as Mock)
        .mockResolvedValueOnce({ data: { parties: [] } })
        .mockRejectedValueOnce(new Error('Service unavailable'));
      const manager = new KeyManager('https://api.example.com', vi.fn().mockReturnValue('t'));

      await expect(manager.fetchPartyKeys(ids)).rejects.toThrow('Service unavailable');
    });

    describe('failures', () => {
      function manager(): KeyManager {
        return new KeyManager('https://api.example.com', vi.fn().mockReturnValue('t'));
      }

      it('passes the server code, status and message through', async () => {
        (mockAxios.post as Mock).mockRejectedValue({
          response: { status: 403, data: { error: { code: 'FORBIDDEN', message: 'Not allowed to look up these parties' } } },
        });

        const error = await manager().fetchPartyKeys(['party_1']).catch((e: unknown) => e);

        expect(error).toBeInstanceOf(CapsaraError);
        expect(error).toMatchObject({ code: 'FORBIDDEN', statusCode: 403, message: 'Not allowed to look up these parties' });
      });

      it('reports an unreachable API as NETWORK_ERROR', async () => {
        (mockAxios.post as Mock).mockRejectedValue({ request: {}, code: 'ECONNRESET', message: 'socket hang up' });

        await expect(manager().fetchPartyKeys(['party_1'])).rejects.toMatchObject({
          code: 'NETWORK_ERROR',
          statusCode: 0,
          details: { originalError: 'socket hang up' },
        });
      });

      it('reports a timeout as NETWORK_ERROR', async () => {
        (mockAxios.post as Mock).mockRejectedValue({ request: {}, code: 'ECONNABORTED', message: 'timeout of 720000ms exceeded' });

        await expect(manager().fetchPartyKeys(['party_1'])).rejects.toMatchObject({ code: 'NETWORK_ERROR', statusCode: 0 });
      });

      it('passes an auth error from a failed refresh through unchanged', async () => {
        const auth = new CapsaraAuthError('Refresh token revoked', 'INVALID_REFRESH_TOKEN', 401);
        (mockAxios.post as Mock).mockRejectedValue(auth);

        await expect(manager().fetchPartyKeys(['party_1'])).rejects.toBe(auth);
      });

      it.each([
        ['HTML text', '<html>gateway</html>'],
        ['an empty body', ''],
        ['JSON null', null],
        ['an array', [keyFor('party_1')]],
      ])('reports a 200 with %s as INVALID_RESPONSE', async (_label, body) => {
        (mockAxios.post as Mock).mockResolvedValue({ status: 200, data: body });

        await expect(manager().fetchPartyKeys(['party_1'])).rejects.toMatchObject({
          name: 'CapsaraError',
          code: 'INVALID_RESPONSE',
          statusCode: 0,
        });
      });

      it.each([
        ['missing', {}],
        ['null', { parties: null }],
        ['not an array', { parties: 'party_1' }],
      ])('returns no parties when parties is %s', async (_label, body) => {
        (mockAxios.post as Mock).mockResolvedValue({ status: 200, data: body });

        await expect(manager().fetchPartyKeys(['party_1'])).resolves.toEqual([]);
      });
    });

    it('sends no request for an empty id list', async () => {
      const manager = new KeyManager('https://api.example.com', vi.fn().mockReturnValue('t'));

      await expect(manager.fetchPartyKeys([])).resolves.toEqual([]);
      expect(mockAxios.post).not.toHaveBeenCalled();
    });
  });
});
