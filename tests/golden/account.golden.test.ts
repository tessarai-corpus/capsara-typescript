/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Account Operations
 * Tests null on error (getCurrentPublicKey), empty on error (getKeyHistory),
 * private key never sent, fingerprint SHA-256 match.
 */

import * as crypto from 'crypto';
import type { AxiosInstance, InternalAxiosRequestConfig } from 'axios';

const { mockAxiosCreate } = vi.hoisted(() => ({
  mockAxiosCreate: vi.fn(),
}));

vi.mock('axios', () => ({
  default: {
    create: mockAxiosCreate,
  },
}));

vi.mock('../../src/internal/config/http-client.js', () => ({
  createAxiosConfig: vi.fn().mockReturnValue({}),
  configureRetryInterceptor: vi.fn(),
  DEFAULT_TIMEOUT_CONFIG: {
    apiTimeout: 60000,
    uploadTimeout: 120000,
    downloadTimeout: 30000,
    requestTimeout: 30000,
    maxSockets: 50,
    keepAlive: true,
  },
}));

import { AccountClient } from '../../src/internal/services/account-service.js';
import { calculateKeyFingerprint } from '../../src/internal/crypto/key-generator.js';

function createMockAxiosInstance(): AxiosInstance {
  const interceptorCallbacks: Array<(config: InternalAxiosRequestConfig) => InternalAxiosRequestConfig> = [];

  return {
    get: vi.fn(),
    post: vi.fn(),
    interceptors: {
      request: {
        use: vi.fn((fn: (config: InternalAxiosRequestConfig) => InternalAxiosRequestConfig) => {
          interceptorCallbacks.push(fn);
        }),
      },
      response: { use: vi.fn() },
    },
  } as unknown as AxiosInstance;
}

describe('Golden: Account', () => {
  let client: AccountClient;
  let mockInstance: AxiosInstance;

  beforeEach(() => {
    vi.clearAllMocks();
    mockInstance = createMockAxiosInstance();
    mockAxiosCreate.mockReturnValue(mockInstance);
    client = new AccountClient('https://api.example.com', () => 'test-token');
  });

  it('should return null only when the account has no key', async () => {
    (mockInstance.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: { publicKey: null, publicKeyFingerprint: null, message: 'No public key' },
    });

    expect(await client.getCurrentPublicKey()).toBeNull();
  });

  it('should throw on error when getting current public key', async () => {
    (mockInstance.get as ReturnType<typeof vi.fn>).mockRejectedValueOnce({
      response: { status: 503, data: { error: { code: 'SERVICE_UNAVAILABLE', message: 'Busy', retryAfter: 2 } } },
    });

    await expect(client.getCurrentPublicKey()).rejects.toMatchObject({
      name: 'CapsaraAccountError',
      code: 'SERVICE_UNAVAILABLE',
      statusCode: 503,
      retryAfter: 2,
    });
  });

  it('should throw on error when getting key history', async () => {
    (mockInstance.get as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Server error'));

    await expect(client.getKeyHistory()).rejects.toMatchObject({
      name: 'CapsaraAccountError',
      code: 'ACCOUNT_ERROR',
      message: 'Server error',
    });
  });

  it('should never send private key to server via addPublicKey', async () => {
    const mockKeyPair = {
      publicKey: '-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----',
      privateKey: '-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----',
      publicKeyFingerprint: 'abc123fingerprint',
    };

    (mockInstance.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: {
        publicKey: mockKeyPair.publicKey,
        publicKeyFingerprint: mockKeyPair.publicKeyFingerprint,
      },
    });

    await client.addPublicKey(mockKeyPair.publicKey, mockKeyPair.publicKeyFingerprint, 'routine rotation');

    const postCallArgs = (mockInstance.post as ReturnType<typeof vi.fn>).mock.calls[0];
    const requestBody = postCallArgs?.[1] as Record<string, unknown>;

    // Verify private key is NOT in the request body
    expect(requestBody).not.toHaveProperty('privateKey');
    expect(JSON.stringify(requestBody)).not.toContain('PRIVATE KEY');
    expect(JSON.stringify(requestBody)).not.toContain('SECRET');

    // Verify public key IS in the request body
    expect(requestBody.publicKey).toBe(mockKeyPair.publicKey);
    expect(requestBody.publicKeyFingerprint).toBe(mockKeyPair.publicKeyFingerprint);
  });

  it('should fingerprint the DER SubjectPublicKeyInfo, independent of PEM layout', () => {
    const { publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 1024,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const der = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
    const expected = crypto.createHash('sha256').update(der).digest('hex');

    expect(calculateKeyFingerprint(publicKey)).toBe(expected);
    expect(calculateKeyFingerprint(publicKey.replace(/\n/g, '\r\n'))).toBe(expected);
    expect(calculateKeyFingerprint(publicKey.trimEnd())).toBe(expected);
  });

  it('should return current public key info on success', async () => {
    // Mock the API response shape (publicKeyFingerprint, not keyFingerprint)
    const apiResponse = {
      publicKey: '-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----',
      publicKeyFingerprint: 'abc123',
    };
    (mockInstance.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: apiResponse });

    const result = await client.getCurrentPublicKey();

    // SDK maps API response to PublicKeyInfo
    expect(result).toEqual({
      publicKey: apiResponse.publicKey,
      keyFingerprint: 'abc123',
      createdAt: '',
      isActive: true,
    });
  });
});
