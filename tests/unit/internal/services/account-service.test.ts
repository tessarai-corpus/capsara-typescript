/**
 * Tests for account-service.ts - Account management and key rotation
 * @file tests/unit/internal/services/account-service.test.ts
 */

import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import type { AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import type { GeneratedKeyPair } from '../../../../src/internal/crypto/key-generator.js';

// Use vi.hoisted for mock functions
const { mockAxiosCreate, mockConfigureRetryInterceptor, mockGenerateKeyPair } = vi.hoisted(() => ({
  mockAxiosCreate: vi.fn(),
  mockConfigureRetryInterceptor: vi.fn(),
  mockGenerateKeyPair: vi.fn(),
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

// Mock key-generator
vi.mock('../../../../src/internal/crypto/key-generator.js', () => ({
  generateKeyPair: mockGenerateKeyPair,
}));

import { AccountClient } from '../../../../src/internal/services/account-service.js';

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

describe('AccountClient', () => {
  let mockAxios: ReturnType<typeof createMockAxiosInstance>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockAxios = createMockAxiosInstance();
    mockAxiosCreate.mockReturnValue(mockAxios);
  });

  describe('constructor', () => {
    it('should create axios instance with base URL', () => {
      const getToken = vi.fn().mockReturnValue('test-token');

      new AccountClient('https://api.example.com', getToken);

      expect(mockAxiosCreate).toHaveBeenCalled();
      expect(mockConfigureRetryInterceptor).toHaveBeenCalled();
    });

    it('should accept custom timeout options', () => {
      const getToken = vi.fn().mockReturnValue(null);

      new AccountClient('https://api.example.com', getToken, {
        apiTimeout: 30000,
      });

      expect(mockAxiosCreate).toHaveBeenCalled();
    });

    it('should accept custom retry options', () => {
      const getToken = vi.fn().mockReturnValue(null);

      new AccountClient('https://api.example.com', getToken, undefined, {
        maxRetries: 5,
        baseDelay: 2000,
      });

      expect(mockConfigureRetryInterceptor).toHaveBeenCalledWith(
        mockAxios,
        expect.objectContaining({ maxRetries: 5, baseDelay: 2000 })
      );
    });

    it('should configure auth interceptor', () => {
      const getToken = vi.fn().mockReturnValue('test-token');

      new AccountClient('https://api.example.com', getToken);

      expect(mockAxios.interceptors.request.use).toHaveBeenCalled();
    });

    it('should add bearer token when available', () => {
      const getToken = vi.fn().mockReturnValue('my-auth-token');

      new AccountClient('https://api.example.com', getToken);

      // Get the interceptor callback
      const callback = mockAxios.interceptorCallbacks[0]!;
      const config = { headers: {} } as InternalAxiosRequestConfig;
      const result = callback(config);

      expect(result.headers.Authorization).toBe('Bearer my-auth-token');
    });

    it('should not add auth header when token is null', () => {
      const getToken = vi.fn().mockReturnValue(null);

      new AccountClient('https://api.example.com', getToken);

      // Get the interceptor callback
      const callback = mockAxios.interceptorCallbacks[0]!;
      const config = { headers: {} } as InternalAxiosRequestConfig;
      const result = callback(config);

      expect(result.headers.Authorization).toBeUndefined();
    });
  });

  describe('getCurrentPublicKey', () => {
    it('should fetch current public key', async () => {
      // Mock the API response shape (publicKeyFingerprint, not keyFingerprint)
      const apiResponse = {
        publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----',
        publicKeyFingerprint: 'SHA256:abc123',
        algorithm: 'RSA-4096',
        keySize: 4096,
        publicExponent: 65537,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: apiResponse });

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      const result = await client.getCurrentPublicKey();

      // SDK maps API response to PublicKeyInfo
      expect(result).toEqual({
        publicKey: apiResponse.publicKey,
        keyFingerprint: 'SHA256:abc123',
        createdAt: '',  // API does not return this
        isActive: true,
      });
      expect(mockAxios.get).toHaveBeenCalledWith('/api/account/key');
    });

    it('should return null when API returns null publicKey', async () => {
      (mockAxios.get as Mock).mockResolvedValue({
        data: { publicKey: null, publicKeyFingerprint: null },
      });

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      const result = await client.getCurrentPublicKey();

      expect(result).toBeNull();
    });

    it('should throw the server error instead of returning null', async () => {
      (mockAxios.get as Mock).mockRejectedValue({
        response: { status: 401, data: { error: { code: 'INVALID_TOKEN', message: 'Token expired' } } },
      });

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      await expect(client.getCurrentPublicKey()).rejects.toMatchObject({
        code: 'INVALID_TOKEN',
        statusCode: 401,
        message: 'Token expired',
      });
    });

    it('should throw NETWORK_ERROR when the API is unreachable', async () => {
      (mockAxios.get as Mock).mockRejectedValue({ request: {}, message: 'ECONNREFUSED' });

      const client = new AccountClient('https://api.example.com', () => 'test-token');

      await expect(client.getCurrentPublicKey()).rejects.toMatchObject({ code: 'NETWORK_ERROR', statusCode: 0 });
    });
  });

  describe('addPublicKey', () => {
    it('should add public key successfully', async () => {
      const apiResponse = {
        publicKey: '-----BEGIN PUBLIC KEY-----\nNewKey...\n-----END PUBLIC KEY-----',
        publicKeyFingerprint: 'SHA256:newkey123',
        message: 'Key added successfully',
      };

      (mockAxios.post as Mock).mockResolvedValue({ data: apiResponse });

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      const result = await client.addPublicKey(
        '-----BEGIN PUBLIC KEY-----\nNewKey...\n-----END PUBLIC KEY-----',
        'SHA256:newkey123'
      );

      expect(result.publicKey).toBe(apiResponse.publicKey);
      expect(result.keyFingerprint).toBe(apiResponse.publicKeyFingerprint);
      expect(result.isActive).toBe(true);
      expect(mockAxios.post).toHaveBeenCalledWith('/api/account/key', {
        publicKey: '-----BEGIN PUBLIC KEY-----\nNewKey...\n-----END PUBLIC KEY-----',
        publicKeyFingerprint: 'SHA256:newkey123',
      });
    });

    it('should include reason when provided', async () => {
      const apiResponse = {
        publicKey: '-----BEGIN PUBLIC KEY-----\nNewKey...\n-----END PUBLIC KEY-----',
        publicKeyFingerprint: 'SHA256:newkey123',
        algorithm: 'RSA-4096',
        keySize: 4096,
        publicExponent: 65537,
      };

      (mockAxios.post as Mock).mockResolvedValue({ data: apiResponse });

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      await client.addPublicKey(
        '-----BEGIN PUBLIC KEY-----\nNewKey...\n-----END PUBLIC KEY-----',
        'SHA256:newkey123',
        'Scheduled key rotation'
      );

      expect(mockAxios.post).toHaveBeenCalledWith('/api/account/key', {
        publicKey: '-----BEGIN PUBLIC KEY-----\nNewKey...\n-----END PUBLIC KEY-----',
        publicKeyFingerprint: 'SHA256:newkey123',
        reason: 'Scheduled key rotation',
      });
    });

    it('should throw CapsaraAccountError on API error', async () => {
      const axiosError = {
        response: {
          status: 400,
          data: { error: { code: 'INVALID_KEY', message: 'Invalid PEM format' } },
        },
        isAxiosError: true,
      };

      (mockAxios.post as Mock).mockRejectedValue(axiosError);

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      await expect(
        client.addPublicKey('invalid-key', 'bad-fingerprint')
      ).rejects.toThrow();
    });
  });

  describe('getKeyHistory', () => {
    it('should fetch key history', async () => {
      // Mock the API response shape (keyHistory array with rotatedAt/rotatedBy)
      const apiResponse = {
        keyHistory: [
          {
            keyFingerprint: 'SHA256:key1',
            rotatedAt: '2024-01-15T10:30:00Z',
            rotatedBy: 'party_abc',
            envelopesAffected: 5,
          },
          {
            keyFingerprint: 'SHA256:key2',
            rotatedAt: '2024-01-01T10:30:00Z',
            rotatedBy: 'party_abc',
            reason: 'Scheduled rotation',
            envelopesAffected: 3,
          },
        ],
        total: 2,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: apiResponse });

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      const result = await client.getKeyHistory();

      expect(result).toEqual([
        {
          keyFingerprint: 'SHA256:key1',
          rotatedAt: '2024-01-15T10:30:00Z',
          rotatedBy: 'party_abc',
          envelopesAffected: 5,
        },
        {
          keyFingerprint: 'SHA256:key2',
          rotatedAt: '2024-01-01T10:30:00Z',
          rotatedBy: 'party_abc',
          reason: 'Scheduled rotation',
          envelopesAffected: 3,
        },
      ]);
      expect(result[0]).not.toHaveProperty('reason');
      expect(result[0]).not.toHaveProperty('publicKey');
      expect(mockAxios.get).toHaveBeenCalledWith('/api/account/key/history');
    });

    it('should return an empty list when the API has no history', async () => {
      (mockAxios.get as Mock).mockResolvedValue({ data: { keyHistory: [], total: 0 } });
      const client = new AccountClient('https://api.example.com', vi.fn().mockReturnValue('t'));

      await expect(client.getKeyHistory()).resolves.toEqual([]);
    });

    it('should drop a null reason and keep nothing beyond the API fields', async () => {
      (mockAxios.get as Mock).mockResolvedValue({
        data: {
          keyHistory: [{ keyFingerprint: 'aa', rotatedAt: '2026-01-01T00:00:00Z', rotatedBy: 'party_x', reason: null, envelopesAffected: 0, extra: 'x' }],
          total: 1,
        },
      });
      const client = new AccountClient('https://api.example.com', vi.fn().mockReturnValue('t'));

      await expect(client.getKeyHistory()).resolves.toEqual([
        { keyFingerprint: 'aa', rotatedAt: '2026-01-01T00:00:00Z', rotatedBy: 'party_x', envelopesAffected: 0 },
      ]);
    });

    it('should throw the server error instead of returning an empty list', async () => {
      (mockAxios.get as Mock).mockRejectedValue({
        response: { status: 500, data: 'Internal Server Error' },
      });

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      await expect(client.getKeyHistory()).rejects.toMatchObject({
        code: 'HTTP_500',
        statusCode: 500,
        message: 'Internal Server Error',
      });
    });
  });

  describe('rotateKey', () => {
    it('should generate key pair and upload public key', async () => {
      const keyPair: GeneratedKeyPair = {
        publicKey: '-----BEGIN PUBLIC KEY-----\nNewGeneratedKey...\n-----END PUBLIC KEY-----',
        privateKey: '-----BEGIN PRIVATE KEY-----\nPrivateKey...\n-----END PRIVATE KEY-----',
        publicKeyFingerprint: 'SHA256:generated123',
        algorithm: 'RSA-4096',
        keySize: 4096,
        publicExponent: 65537,
      };

      mockGenerateKeyPair.mockResolvedValue(keyPair);

      const apiResponse = {
        publicKey: keyPair.publicKey,
        publicKeyFingerprint: keyPair.publicKeyFingerprint,
      };

      (mockAxios.post as Mock).mockResolvedValue({ data: apiResponse });

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      const result = await client.rotateKey();

      expect(result.keyPair).toEqual(keyPair);
      expect(result.serverInfo.publicKey).toBe(keyPair.publicKey);
      expect(result.serverInfo.keyFingerprint).toBe(keyPair.publicKeyFingerprint);
      expect(result.serverInfo.isActive).toBe(true);
      expect(mockGenerateKeyPair).toHaveBeenCalled();
      expect(mockAxios.post).toHaveBeenCalledWith('/api/account/key', {
        publicKey: keyPair.publicKey,
        publicKeyFingerprint: keyPair.publicKeyFingerprint,
      });
    });

    describe('key pair hand-off', () => {
      const keyPair: GeneratedKeyPair = {
        publicKey: 'pub-pem',
        privateKey: 'priv-pem',
        publicKeyFingerprint: 'fp_new',
        algorithm: 'RSA-4096',
        keySize: 4096,
        publicExponent: 65537,
      };

      it('hands the new key pair to the caller before registering it', async () => {
        mockGenerateKeyPair.mockResolvedValue(keyPair);
        (mockAxios.post as Mock).mockResolvedValue({ data: { publicKey: 'pub-pem', publicKeyFingerprint: 'fp_new' } });
        const order: string[] = [];
        const onKeyPairGenerated = vi.fn(async () => { order.push('callback'); });
        (mockAxios.post as Mock).mockImplementation(async () => {
          order.push('post');
          return { data: { publicKey: 'pub-pem', publicKeyFingerprint: 'fp_new' } };
        });
        const client = new AccountClient('https://api.example.com', vi.fn().mockReturnValue('t'));

        const result = await client.rotateKey({ onKeyPairGenerated, reason: 'scheduled' });

        expect(onKeyPairGenerated).toHaveBeenCalledWith(keyPair);
        expect(order).toEqual(['callback', 'post']);
        expect(mockAxios.post).toHaveBeenCalledWith('/api/account/key', {
          publicKey: 'pub-pem',
          publicKeyFingerprint: 'fp_new',
          reason: 'scheduled',
        });
        expect(result.keyPair).toBe(keyPair);
      });

      it('has already handed over the key pair when registration fails', async () => {
        mockGenerateKeyPair.mockResolvedValue(keyPair);
        (mockAxios.post as Mock).mockRejectedValue(Object.assign(new Error('socket hang up'), { request: {} }));
        const onKeyPairGenerated = vi.fn();
        const client = new AccountClient('https://api.example.com', vi.fn().mockReturnValue('t'));

        await expect(client.rotateKey({ onKeyPairGenerated })).rejects.toMatchObject({ code: 'NETWORK_ERROR' });
        expect(onKeyPairGenerated).toHaveBeenCalledWith(keyPair);
      });

      it('does not register the key when the caller cannot keep it', async () => {
        mockGenerateKeyPair.mockResolvedValue(keyPair);
        const client = new AccountClient('https://api.example.com', vi.fn().mockReturnValue('t'));

        await expect(client.rotateKey({ onKeyPairGenerated: () => { throw new Error('vault unavailable'); } }))
          .rejects.toThrow('vault unavailable');
        expect(mockAxios.post).not.toHaveBeenCalled();
      });
    });

    it('should propagate key generation errors', async () => {
      mockGenerateKeyPair.mockRejectedValue(new Error('Key generation failed'));

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      await expect(client.rotateKey()).rejects.toThrow('Key generation failed');
    });

    it('should propagate API errors from addPublicKey', async () => {
      const keyPair: GeneratedKeyPair = {
        publicKey: '-----BEGIN PUBLIC KEY-----\nKey...\n-----END PUBLIC KEY-----',
        privateKey: '-----BEGIN PRIVATE KEY-----\nPrivate...\n-----END PRIVATE KEY-----',
        publicKeyFingerprint: 'SHA256:test',
        algorithm: 'RSA-4096',
        keySize: 4096,
        publicExponent: 65537,
      };

      mockGenerateKeyPair.mockResolvedValue(keyPair);

      const axiosError = {
        response: {
          status: 401,
          data: { error: { code: 'UNAUTHORIZED', message: 'Not authenticated' } },
        },
        isAxiosError: true,
      };

      (mockAxios.post as Mock).mockRejectedValue(axiosError);

      const getToken = vi.fn().mockReturnValue('test-token');
      const client = new AccountClient('https://api.example.com', getToken);

      await expect(client.rotateKey()).rejects.toThrow();
    });
  });

  describe('unexpected 2xx bodies', () => {
    const invalidResponse = { name: 'CapsaraAccountError', code: 'INVALID_RESPONSE', statusCode: 0 };
    const nonObjectBodies: Array<[string, unknown]> = [
      ['HTML text', '<html>proxy</html>'],
      ['an empty body', ''],
      ['JSON null', null],
      ['an array', [{ publicKey: 'PEM' }]],
      ['a number', 42],
    ];

    it.each(nonObjectBodies)('getCurrentPublicKey throws INVALID_RESPONSE for %s', async (_label, body) => {
      (mockAxios.get as Mock).mockResolvedValue({ status: 200, data: body });
      const client = new AccountClient('https://api.example.com', () => 'token');

      await expect(client.getCurrentPublicKey()).rejects.toMatchObject(invalidResponse);
    });

    it.each(nonObjectBodies)('addPublicKey throws INVALID_RESPONSE for %s', async (_label, body) => {
      (mockAxios.post as Mock).mockResolvedValue({ status: 200, data: body });
      const client = new AccountClient('https://api.example.com', () => 'token');

      await expect(client.addPublicKey('PEM', 'fp')).rejects.toMatchObject(invalidResponse);
    });

    it.each(nonObjectBodies)('getKeyHistory throws INVALID_RESPONSE for %s', async (_label, body) => {
      (mockAxios.get as Mock).mockResolvedValue({ status: 200, data: body });
      const client = new AccountClient('https://api.example.com', () => 'token');

      await expect(client.getKeyHistory()).rejects.toMatchObject(invalidResponse);
    });

    it.each([
      ['publicKey null', { publicKey: null, publicKeyFingerprint: null }],
      ['publicKey empty', { publicKey: '', publicKeyFingerprint: '' }],
      ['publicKey missing', {}],
    ])('getCurrentPublicKey returns null for an object with %s', async (_label, body) => {
      (mockAxios.get as Mock).mockResolvedValue({ status: 200, data: body });
      const client = new AccountClient('https://api.example.com', () => 'token');

      await expect(client.getCurrentPublicKey()).resolves.toBeNull();
    });

    it.each([
      ['missing', {}],
      ['null', { envelopesAffected: null }],
    ])('getKeyHistory returns envelopesAffected null when it is %s', async (_label, extra) => {
      (mockAxios.get as Mock).mockResolvedValue({
        status: 200,
        data: { keyHistory: [{ keyFingerprint: 'aa', rotatedAt: '2026-01-01T00:00:00Z', rotatedBy: 'party_x', ...extra }] },
      });
      const client = new AccountClient('https://api.example.com', () => 'token');

      const [entry] = await client.getKeyHistory();

      expect(entry).toStrictEqual({ keyFingerprint: 'aa', rotatedAt: '2026-01-01T00:00:00Z', rotatedBy: 'party_x', envelopesAffected: null });
    });

    it('getKeyHistory keeps envelopesAffected 0 as 0', async () => {
      (mockAxios.get as Mock).mockResolvedValue({
        status: 200,
        data: { keyHistory: [{ keyFingerprint: 'aa', rotatedAt: 'x', rotatedBy: 'p', envelopesAffected: 0 }] },
      });
      const client = new AccountClient('https://api.example.com', () => 'token');

      await expect(client.getKeyHistory()).resolves.toMatchObject([{ envelopesAffected: 0 }]);
    });

    it('getKeyHistory returns an empty list for an object without keyHistory', async () => {
      (mockAxios.get as Mock).mockResolvedValue({ status: 200, data: { total: 0 } });
      const client = new AccountClient('https://api.example.com', () => 'token');

      await expect(client.getKeyHistory()).resolves.toEqual([]);
    });

    it('rotateKey fails with INVALID_RESPONSE after the key pair callback when the body is unusable', async () => {
      const keyPair = { publicKey: 'PEM', privateKey: 'PRIV', publicKeyFingerprint: 'fp' } as GeneratedKeyPair;
      mockGenerateKeyPair.mockResolvedValue(keyPair);
      (mockAxios.post as Mock).mockResolvedValue({ status: 200, data: 'not json' });
      const onKeyPairGenerated = vi.fn();
      const client = new AccountClient('https://api.example.com', () => 'token');

      await expect(client.rotateKey({ onKeyPairGenerated })).rejects.toMatchObject(invalidResponse);
      expect(onKeyPairGenerated).toHaveBeenCalledWith(keyPair);
    });
  });
});
