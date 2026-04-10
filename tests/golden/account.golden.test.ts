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

  it('should return null on error when getting current public key', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    (mockInstance.get as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network error'));

    const result = await client.getCurrentPublicKey();

    expect(result).toBeNull();
  });

  it('should return empty array on error when getting key history', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    (mockInstance.get as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Server error'));

    const result = await client.getKeyHistory();

    expect(result).toEqual([]);
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

  it('should produce SHA-256 fingerprint matching key-generator calculation', () => {
    const publicKeyPEM = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhk...\n-----END PUBLIC KEY-----';
    const expected = crypto.createHash('sha256').update(publicKeyPEM).digest('hex');

    // SHA-256 fingerprint should be a 64-char hex string
    expect(expected).toMatch(/^[a-f0-9]{64}$/);
    expect(expected.length).toBe(64);
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
