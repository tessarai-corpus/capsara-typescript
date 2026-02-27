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

  describe('fetchExplicitPartyKey', () => {
    it('should fetch single party key', async () => {
      const partyKey: PartyKey = {
        id: 'party_123',
        publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----',
        fingerprint: 'SHA256:abc123',
      };

      (mockAxios.post as Mock).mockResolvedValue({
        data: { parties: [partyKey] },
      });

      const getToken = vi.fn().mockReturnValue('test-token');
      const manager = new KeyManager('https://api.example.com', getToken);

      const result = await manager.fetchExplicitPartyKey('party_123');

      expect(result).toEqual(partyKey);
      expect(mockAxios.post).toHaveBeenCalledWith('/api/party/keys', {
        ids: ['party_123'],
      });
    });

    it('should return undefined when party not found', async () => {
      (mockAxios.post as Mock).mockResolvedValue({
        data: { parties: [] },
      });

      const getToken = vi.fn().mockReturnValue('test-token');
      const manager = new KeyManager('https://api.example.com', getToken);

      const result = await manager.fetchExplicitPartyKey('nonexistent_party');

      expect(result).toBeUndefined();
    });

    it('should return only the requested party excluding delegates', async () => {
      const requestedParty: PartyKey = {
        id: 'party_123',
        publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----',
        fingerprint: 'SHA256:abc123',
      };

      const delegateParty: PartyKey = {
        id: 'delegate_456',
        publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjXYZ...\n-----END PUBLIC KEY-----',
        fingerprint: 'SHA256:xyz789',
      };

      // API returns both the requested party and its delegates
      (mockAxios.post as Mock).mockResolvedValue({
        data: { parties: [requestedParty, delegateParty] },
      });

      const getToken = vi.fn().mockReturnValue('test-token');
      const manager = new KeyManager('https://api.example.com', getToken);

      const result = await manager.fetchExplicitPartyKey('party_123');

      expect(result).toEqual(requestedParty);
      expect(result?.id).toBe('party_123');
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

      // fetchPartyKeys includes delegates (unlike fetchExplicitPartyKey)
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
  });
});
