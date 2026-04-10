/**
 * Tests for capsara-client.ts - Capsara SDK Client
 * @file tests/unit/client/capsara-client.test.ts
 */

import { describe, it, expect, vi, beforeEach, type Mock, afterEach } from 'vitest';
import type { AxiosInstance, InternalAxiosRequestConfig, AxiosResponse } from 'axios';
import type { SystemLimits, AuthResponse } from '../../../src/types/index.js';
import type { DecryptedCapsa } from '../../../src/internal/decryptor/capsa-decryptor.js';

// Use vi.hoisted for mock functions
const {
  mockAxiosCreate,
  mockConfigureRetryInterceptor,
  mockAuthServiceLogin,
  mockAuthServiceLogout,
  mockAuthServiceGetToken,
  mockAuthServiceSetToken,
  mockAuthServiceIsAuthenticated,
  mockAuthServiceCanRefresh,
  mockAuthServiceRefresh,
  mockAuthServiceGetLastRefreshError,
  mockKeyManagerFetchPartyKeys,
  mockKeyManagerFetchExplicitPartyKey,
  mockLimitsManagerGetLimits,
  mockLimitsManagerClearCache,
  mockAccountClientGetCurrentPublicKey,
  mockAccountClientAddPublicKey,
  mockAccountClientGetKeyHistory,
  mockAccountClientRotateKey,
  mockCapsaServiceGetCapsa,
  mockCapsaServiceGetDecryptedCapsa,
  mockCapsaServiceListCapsas,
  mockCapsaServiceDeleteCapsa,
  mockDownloadServiceDownloadAndDecryptFile,
  mockUploadServiceSendCapsas,
  mockAuditServiceGetAuditEntries,
  mockAuditServiceCreateAuditEntry,
  mockDecryptedCapsaCacheSet,
  mockDecryptedCapsaCacheClear,
  mockDecryptedCapsaCacheClearAll,
  mockDecryptedCapsaCacheGetMasterKey,
  mockDecryptedCapsaCacheGetFileMetadata,
  mockGenerateKeyPair,
} = vi.hoisted(() => ({
  mockAxiosCreate: vi.fn(),
  mockConfigureRetryInterceptor: vi.fn(),
  mockAuthServiceLogin: vi.fn(),
  mockAuthServiceLogout: vi.fn(),
  mockAuthServiceGetToken: vi.fn(),
  mockAuthServiceSetToken: vi.fn(),
  mockAuthServiceIsAuthenticated: vi.fn(),
  mockAuthServiceCanRefresh: vi.fn(),
  mockAuthServiceRefresh: vi.fn(),
  mockAuthServiceGetLastRefreshError: vi.fn(),
  mockKeyManagerFetchPartyKeys: vi.fn(),
  mockKeyManagerFetchExplicitPartyKey: vi.fn(),
  mockLimitsManagerGetLimits: vi.fn(),
  mockLimitsManagerClearCache: vi.fn(),
  mockAccountClientGetCurrentPublicKey: vi.fn(),
  mockAccountClientAddPublicKey: vi.fn(),
  mockAccountClientGetKeyHistory: vi.fn(),
  mockAccountClientRotateKey: vi.fn(),
  mockCapsaServiceGetCapsa: vi.fn(),
  mockCapsaServiceGetDecryptedCapsa: vi.fn(),
  mockCapsaServiceListCapsas: vi.fn(),
  mockCapsaServiceDeleteCapsa: vi.fn(),
  mockDownloadServiceDownloadAndDecryptFile: vi.fn(),
  mockUploadServiceSendCapsas: vi.fn(),
  mockAuditServiceGetAuditEntries: vi.fn(),
  mockAuditServiceCreateAuditEntry: vi.fn(),
  mockDecryptedCapsaCacheSet: vi.fn(),
  mockDecryptedCapsaCacheClear: vi.fn(),
  mockDecryptedCapsaCacheClearAll: vi.fn(),
  mockDecryptedCapsaCacheGetMasterKey: vi.fn(),
  mockDecryptedCapsaCacheGetFileMetadata: vi.fn(),
  mockGenerateKeyPair: vi.fn(),
}));

// Mock axios
vi.mock('axios', () => ({
  default: {
    create: mockAxiosCreate,
  },
}));

// Mock http-client
vi.mock('../../../src/internal/config/http-client.js', () => ({
  createAxiosConfig: vi.fn().mockReturnValue({
    baseURL: 'https://api.example.com',
    timeout: 60000,
    headers: { 'Content-Type': 'application/json' },
  }),
  configureRetryInterceptor: mockConfigureRetryInterceptor,
  createHttpAgent: vi.fn().mockReturnValue({}),
  createHttpsAgent: vi.fn().mockReturnValue({}),
  DEFAULT_TIMEOUT_CONFIG: {
    apiTimeout: 60000,
    uploadTimeout: 120000,
    downloadTimeout: 30000,
    requestTimeout: 30000,
    maxSockets: 50,
    keepAlive: true,
  },
}));

// Mock services
vi.mock('../../../src/internal/services/auth-service.js', () => ({
  AuthService: vi.fn().mockImplementation(() => ({
    login: mockAuthServiceLogin,
    logout: mockAuthServiceLogout,
    getToken: mockAuthServiceGetToken,
    setToken: mockAuthServiceSetToken,
    isAuthenticated: mockAuthServiceIsAuthenticated,
    canRefresh: mockAuthServiceCanRefresh,
    refresh: mockAuthServiceRefresh,
    getLastRefreshError: mockAuthServiceGetLastRefreshError,
  })),
}));

vi.mock('../../../src/internal/services/key-service.js', () => ({
  KeyManager: vi.fn().mockImplementation(() => ({
    fetchPartyKeys: mockKeyManagerFetchPartyKeys,
    fetchExplicitPartyKey: mockKeyManagerFetchExplicitPartyKey,
  })),
}));

vi.mock('../../../src/internal/services/limits-service.js', () => ({
  LimitsManager: vi.fn().mockImplementation(() => ({
    getLimits: mockLimitsManagerGetLimits,
    clearCache: mockLimitsManagerClearCache,
  })),
}));

vi.mock('../../../src/internal/services/account-service.js', () => ({
  AccountClient: vi.fn().mockImplementation(() => ({
    getCurrentPublicKey: mockAccountClientGetCurrentPublicKey,
    addPublicKey: mockAccountClientAddPublicKey,
    getKeyHistory: mockAccountClientGetKeyHistory,
    rotateKey: mockAccountClientRotateKey,
  })),
}));

vi.mock('../../../src/internal/services/capsa-service.js', () => ({
  CapsaService: vi.fn().mockImplementation(() => ({
    getCapsa: mockCapsaServiceGetCapsa,
    getDecryptedCapsa: mockCapsaServiceGetDecryptedCapsa,
    listCapsas: mockCapsaServiceListCapsas,
    deleteCapsa: mockCapsaServiceDeleteCapsa,
  })),
}));

vi.mock('../../../src/internal/services/download-service.js', () => ({
  DownloadService: vi.fn().mockImplementation(() => ({
    downloadAndDecryptFile: mockDownloadServiceDownloadAndDecryptFile,
  })),
}));

vi.mock('../../../src/internal/services/upload-service.js', () => ({
  UploadService: vi.fn().mockImplementation(() => ({
    sendCapsas: mockUploadServiceSendCapsas,
  })),
}));

vi.mock('../../../src/internal/services/audit-service.js', () => ({
  AuditService: vi.fn().mockImplementation(() => ({
    getAuditEntries: mockAuditServiceGetAuditEntries,
    createAuditEntry: mockAuditServiceCreateAuditEntry,
  })),
}));

vi.mock('../../../src/internal/capsa-cache.js', () => ({
  DecryptedCapsaCache: vi.fn().mockImplementation(() => ({
    set: mockDecryptedCapsaCacheSet,
    clear: mockDecryptedCapsaCacheClear,
    clearAll: mockDecryptedCapsaCacheClearAll,
    getMasterKey: mockDecryptedCapsaCacheGetMasterKey,
    getFileMetadata: mockDecryptedCapsaCacheGetFileMetadata,
  })),
}));

vi.mock('../../../src/internal/crypto/key-generator.js', () => ({
  generateKeyPair: mockGenerateKeyPair,
}));

vi.mock('../../../src/builder/capsa-builder.js', () => ({
  CapsaBuilder: vi.fn().mockImplementation((creatorId, privateKey, limits) => ({
    creatorId,
    privateKey,
    limits,
    addRecipient: vi.fn().mockReturnThis(),
    addFile: vi.fn().mockReturnThis(),
    getRecipientIds: vi.fn().mockReturnValue([]),
  })),
}));

import { CapsaraClient, type CapsaraClientOptions } from '../../../src/client/capsara-client.js';

// Helper to create mock axios instance with interceptor support
function createMockAxiosInstance(): AxiosInstance & {
  requestInterceptors: Array<{
    onFulfilled: (config: InternalAxiosRequestConfig) => InternalAxiosRequestConfig;
    onRejected?: (error: unknown) => unknown;
  }>;
  responseInterceptors: Array<{
    onFulfilled: (response: AxiosResponse) => AxiosResponse;
    onRejected?: (error: unknown) => Promise<unknown>;
  }>;
} {
  const requestInterceptors: Array<{
    onFulfilled: (config: InternalAxiosRequestConfig) => InternalAxiosRequestConfig;
    onRejected?: (error: unknown) => unknown;
  }> = [];
  const responseInterceptors: Array<{
    onFulfilled: (response: AxiosResponse) => AxiosResponse;
    onRejected?: (error: unknown) => Promise<unknown>;
  }> = [];

  const instance = {
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
        use: vi.fn((onFulfilled, onRejected) => {
          requestInterceptors.push({ onFulfilled, onRejected });
          return requestInterceptors.length - 1;
        }),
        eject: vi.fn(),
        clear: vi.fn(),
      },
      response: {
        use: vi.fn((onFulfilled, onRejected) => {
          responseInterceptors.push({ onFulfilled, onRejected });
          return responseInterceptors.length - 1;
        }),
        eject: vi.fn(),
        clear: vi.fn(),
      },
    },
    requestInterceptors,
    responseInterceptors,
  } as unknown as AxiosInstance & {
    requestInterceptors: typeof requestInterceptors;
    responseInterceptors: typeof responseInterceptors;
  };

  return instance;
}

describe('CapsaraClient', () => {
  let mockAxios: ReturnType<typeof createMockAxiosInstance>;
  const defaultLimits: SystemLimits = {
    maxFileSize: 50 * 1024 * 1024,
    maxFilesPerCapsa: 100,
    maxTotalSize: 500 * 1024 * 1024,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockAxios = createMockAxiosInstance();
    mockAxiosCreate.mockReturnValue(mockAxios);
    mockLimitsManagerGetLimits.mockResolvedValue(defaultLimits);
    mockAuthServiceGetToken.mockReturnValue('test-token');
    mockAuthServiceLogout.mockResolvedValue(true);
  });

  describe('constructor', () => {
    it('should create client with base URL', () => {
      const client = new CapsaraClient('https://api.example.com');
      expect(client).toBeInstanceOf(CapsaraClient);
      expect(mockAxiosCreate).toHaveBeenCalled();
    });

    it('should create client with custom options', () => {
      const options: CapsaraClientOptions = {
        timeout: { apiTimeout: 30000 },
        retry: { maxRetries: 5 },
        maxBatchSize: 200,
        cacheTTL: 10 * 60 * 1000,
      };

      const client = new CapsaraClient('https://api.example.com', options);
      expect(client).toBeInstanceOf(CapsaraClient);
    });

    it('should auto-login with credentials', async () => {
      const authResponse: AuthResponse = {
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };
      mockAuthServiceLogin.mockResolvedValue(authResponse);

      new CapsaraClient('https://api.example.com', {
        credentials: { clientId: 'id', clientSecret: 'secret' },
      });

      // Wait for async auto-login
      await new Promise(resolve => setTimeout(resolve, 10));
      expect(mockAuthServiceLogin).toHaveBeenCalledWith({ clientId: 'id', clientSecret: 'secret' });
    });

    it('should set access token when provided', () => {
      new CapsaraClient('https://api.example.com', {
        accessToken: 'pre-existing-token',
      });

      expect(mockAuthServiceSetToken).toHaveBeenCalledWith('pre-existing-token');
    });

    it('should configure auth request interceptor', () => {
      const client = new CapsaraClient('https://api.example.com');
      expect(mockAxios.interceptors.request.use).toHaveBeenCalled();
    });

    it('should configure auth response interceptor for 401 refresh', () => {
      const client = new CapsaraClient('https://api.example.com');
      expect(mockAxios.interceptors.response.use).toHaveBeenCalled();
    });
  });

  describe('authentication', () => {
    it('should login with credentials', async () => {
      const authResponse: AuthResponse = {
        party: { id: 'party_123', email: 'test@example.com', name: 'Test', kind: 'organization' },
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresIn: 3600,
      };
      mockAuthServiceLogin.mockResolvedValue(authResponse);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.login({ clientId: 'id', clientSecret: 'secret' });

      expect(result).toEqual(authResponse);
      expect(mockAuthServiceLogin).toHaveBeenCalledWith({ clientId: 'id', clientSecret: 'secret' });
    });

    it('should logout and clear cache', async () => {
      const client = new CapsaraClient('https://api.example.com');
      const result = await client.logout();

      expect(result).toBe(true);
      expect(mockDecryptedCapsaCacheClearAll).toHaveBeenCalled();
      expect(mockAuthServiceLogout).toHaveBeenCalled();
    });

    it('should check authentication status', () => {
      mockAuthServiceIsAuthenticated.mockReturnValue(true);

      const client = new CapsaraClient('https://api.example.com');
      expect(client.isAuthenticated()).toBe(true);
    });

    it('should set private key', () => {
      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey('-----BEGIN PRIVATE KEY-----\nKey\n-----END PRIVATE KEY-----');
      // Identity is private, but we can test it by creating a builder
    });
  });

  describe('capsa operations', () => {
    it('should create capsa builder with limits', async () => {
      mockAuthServiceLogin.mockResolvedValue({
        party: { id: 'party_123', email: 'test@example.com', name: 'Test', kind: 'organization' },
        accessToken: 'token', refreshToken: 'refresh', expiresIn: 3600,
      });

      const client = new CapsaraClient('https://api.example.com');
      await client.login({ clientId: 'id', clientSecret: 'secret' });
      client.setPrivateKey('-----BEGIN PRIVATE KEY-----\nKey\n-----END PRIVATE KEY-----');

      const builder = await client.createCapsaBuilder();

      expect(mockLimitsManagerGetLimits).toHaveBeenCalled();
      expect(builder).toBeDefined();
    });

    it('should throw if creating builder without identity', async () => {
      const client = new CapsaraClient('https://api.example.com');

      await expect(client.createCapsaBuilder()).rejects.toThrow(/Creator identity not set\. Call login\(\) and setPrivateKey\(\) first\./);
    });

    it('should send capsas', async () => {
      const sendResult = {
        batchId: 'batch_123',
        successful: 1,
        failed: 0,
        created: [{ packageId: 'capsa_123', index: 0 }],
      };
      mockUploadServiceSendCapsas.mockResolvedValue(sendResult);
      mockAuthServiceLogin.mockResolvedValue({
        party: { id: 'party_123', email: 'test@example.com', name: 'Test', kind: 'organization' },
        accessToken: 'token', refreshToken: 'refresh', expiresIn: 3600,
      });

      const client = new CapsaraClient('https://api.example.com');
      await client.login({ clientId: 'id', clientSecret: 'secret' });
      client.setPrivateKey('-----BEGIN PRIVATE KEY-----\nKey\n-----END PRIVATE KEY-----');

      const result = await client.sendCapsas([]);

      expect(result).toEqual(sendResult);
    });

    it('should throw if sending without identity', async () => {
      const client = new CapsaraClient('https://api.example.com');

      await expect(client.sendCapsas([])).rejects.toThrow(/Creator identity not set\. Call login\(\) and setPrivateKey\(\) first\./);
    });

    it('should get encrypted capsa when decrypt=false', async () => {
      const capsa = { id: 'capsa_123', creator: 'party_123', status: 'active' };
      mockCapsaServiceGetCapsa.mockResolvedValue(capsa);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.getCapsa('capsa_123', { decrypt: false });

      expect(result).toEqual(capsa);
      expect(mockCapsaServiceGetCapsa).toHaveBeenCalledWith('capsa_123');
    });

    it('should get and decrypt capsa by default', async () => {
      const decrypted: DecryptedCapsa = {
        id: 'capsa_123',
        creator: 'party_123',
        status: 'active',
        createdAt: '2024-01-15T10:30:00Z',
        masterKey: 'master-key',
        metadata: {},
        files: [],
        signatureValid: true,
        _masterKey: Buffer.from('master-key-bytes'),
      };
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decrypted);

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey('-----BEGIN PRIVATE KEY-----\nKey\n-----END PRIVATE KEY-----');

      const result = await client.getCapsa('capsa_123');

      expect(result).toEqual(decrypted);
      expect(mockDecryptedCapsaCacheSet).toHaveBeenCalled();
    });

    it('should throw if decrypting without identity', async () => {
      const client = new CapsaraClient('https://api.example.com');

      await expect(client.getCapsa('capsa_123')).rejects.toThrow(/Private key required\. Call setPrivateKey\(\) first\./);
    });

    it('should deduplicate concurrent getCapsa requests', async () => {
      const decrypted: DecryptedCapsa = {
        id: 'capsa_123',
        creator: 'party_123',
        status: 'active',
        createdAt: '2024-01-15T10:30:00Z',
        masterKey: 'master-key',
        metadata: {},
        files: [],
        signatureValid: true,
        _masterKey: Buffer.from('master-key-bytes'),
      };
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decrypted);

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey('-----BEGIN PRIVATE KEY-----\nKey\n-----END PRIVATE KEY-----');

      // Fire two concurrent requests
      const [result1, result2] = await Promise.all([
        client.getCapsa('capsa_123'),
        client.getCapsa('capsa_123'),
      ]);

      expect(result1).toEqual(result2);
      // Should only call service once
      expect(mockCapsaServiceGetDecryptedCapsa).toHaveBeenCalledTimes(1);
    });

    it('should list capsas', async () => {
      const response = { capsas: [], pagination: { limit: 20, hasMore: false } };
      mockCapsaServiceListCapsas.mockResolvedValue(response);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.listCapsas({ status: 'active' });

      expect(result).toEqual(response);
    });

    it('should delete capsa and clear cache', async () => {
      mockCapsaServiceDeleteCapsa.mockResolvedValue(undefined);

      const client = new CapsaraClient('https://api.example.com');
      await client.deleteCapsa('capsa_123');

      expect(mockDecryptedCapsaCacheClear).toHaveBeenCalledWith('capsa_123');
      expect(mockCapsaServiceDeleteCapsa).toHaveBeenCalledWith('capsa_123');
    });
  });

  describe('file operations', () => {
    it('should download file using cached data', async () => {
      mockDecryptedCapsaCacheGetMasterKey.mockReturnValue('master-key');
      mockDecryptedCapsaCacheGetFileMetadata.mockReturnValue({
        iv: 'iv',
        authTag: 'tag',
        encryptedFilename: 'name',
        filenameIV: 'fiv',
        filenameAuthTag: 'ftag',
      });
      mockDownloadServiceDownloadAndDecryptFile.mockResolvedValue({
        data: Buffer.from('file content'),
        filename: 'test.txt',
      });

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.downloadFile('capsa_123', 'file_001');

      expect(result.filename).toBe('test.txt');
      expect(mockCapsaServiceGetDecryptedCapsa).not.toHaveBeenCalled();
    });

    it('should auto-fetch capsa if not cached', async () => {
      // First call returns null (not cached)
      mockDecryptedCapsaCacheGetMasterKey.mockReturnValueOnce(null);
      mockDecryptedCapsaCacheGetFileMetadata.mockReturnValueOnce(null);

      // After fetch, return cached values
      mockDecryptedCapsaCacheGetMasterKey.mockReturnValue('master-key');
      mockDecryptedCapsaCacheGetFileMetadata.mockReturnValue({
        iv: 'iv',
        authTag: 'tag',
        encryptedFilename: 'name',
        filenameIV: 'fiv',
        filenameAuthTag: 'ftag',
      });

      const decrypted: DecryptedCapsa = {
        id: 'capsa_123',
        creator: 'party_123',
        status: 'active',
        createdAt: '2024-01-15T10:30:00Z',
        masterKey: 'master-key',
        metadata: {},
        files: [{ fileId: 'file_001', filename: 'test.txt', size: 100, mimetype: 'text/plain', iv: 'iv', authTag: 'tag' }],
        signatureValid: true,
        _masterKey: Buffer.from('master-key-bytes'),
      };
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decrypted);
      mockDownloadServiceDownloadAndDecryptFile.mockResolvedValue({
        data: Buffer.from('content'),
        filename: 'test.txt',
      });

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey('-----BEGIN PRIVATE KEY-----\nKey\n-----END PRIVATE KEY-----');

      const result = await client.downloadFile('capsa_123', 'file_001');

      expect(mockCapsaServiceGetDecryptedCapsa).toHaveBeenCalled();
      expect(result.filename).toBe('test.txt');
    });

    it('should throw if file not found in capsa', async () => {
      mockDecryptedCapsaCacheGetMasterKey.mockReturnValue(null);
      mockDecryptedCapsaCacheGetFileMetadata.mockReturnValue(null);

      const decrypted: DecryptedCapsa = {
        id: 'capsa_123',
        creator: 'party_123',
        status: 'active',
        createdAt: '2024-01-15T10:30:00Z',
        masterKey: 'master-key',
        metadata: {},
        files: [],
        signatureValid: true,
        _masterKey: Buffer.from('master-key-bytes'),
      };
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decrypted);

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey('-----BEGIN PRIVATE KEY-----\nKey\n-----END PRIVATE KEY-----');

      await expect(client.downloadFile('capsa_123', 'file_missing')).rejects.toThrow(/not found/);
    });
  });

  describe('audit operations', () => {
    it('should get audit entries', async () => {
      const response = { entries: [], hasMore: false };
      mockAuditServiceGetAuditEntries.mockResolvedValue(response);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.getAuditEntries('capsa_123');

      expect(result).toEqual(response);
    });

    it('should create audit entry', async () => {
      const response = { success: true, message: 'Created' };
      mockAuditServiceCreateAuditEntry.mockResolvedValue(response);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.createAuditEntry('capsa_123', { action: 'accessed' });

      expect(result).toEqual(response);
    });
  });

  describe('account operations', () => {
    it('should get current public key', async () => {
      const keyInfo = {
        publicKey: '-----BEGIN PUBLIC KEY-----\nKey\n-----END PUBLIC KEY-----',
        keyFingerprint: 'SHA256:abc',
        createdAt: '2024-01-15T10:30:00Z',
        isActive: true,
      };
      mockAccountClientGetCurrentPublicKey.mockResolvedValue(keyInfo);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.getCurrentPublicKey();

      expect(result).toEqual(keyInfo);
    });

    it('should add public key', async () => {
      const keyInfo = {
        publicKey: '-----BEGIN PUBLIC KEY-----\nKey\n-----END PUBLIC KEY-----',
        keyFingerprint: 'SHA256:abc',
        createdAt: '2024-01-15T10:30:00Z',
        isActive: true,
      };
      mockAccountClientAddPublicKey.mockResolvedValue(keyInfo);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.addPublicKey('pubkey', 'fingerprint', 'reason');

      expect(result).toEqual(keyInfo);
    });

    it('should get key history', async () => {
      const history = [{ publicKey: 'key', keyFingerprint: 'fp', createdAt: '2024-01-01', isActive: true }];
      mockAccountClientGetKeyHistory.mockResolvedValue(history);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.getKeyHistory();

      expect(result).toEqual(history);
    });

    it('should rotate key', async () => {
      const rotateResult = {
        keyPair: { publicKey: 'pub', privateKey: 'priv', publicKeyFingerprint: 'fp' },
        serverInfo: { publicKey: 'pub', keyFingerprint: 'fp', createdAt: '2024-01-01', isActive: true },
      };
      mockAccountClientRotateKey.mockResolvedValue(rotateResult);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.rotateKey();

      expect(result).toEqual(rotateResult);
    });
  });

  describe('utilities', () => {
    it('should get limits', async () => {
      const client = new CapsaraClient('https://api.example.com');
      const limits = await client.getLimits();

      expect(limits).toEqual(defaultLimits);
    });

    it('should generate key pair (static)', async () => {
      const keyPair = { publicKey: 'pub', privateKey: 'priv', publicKeyFingerprint: 'fp' };
      mockGenerateKeyPair.mockResolvedValue(keyPair);

      const result = await CapsaraClient.generateKeyPair();

      expect(result).toEqual(keyPair);
    });

    it('should clear cache', () => {
      const client = new CapsaraClient('https://api.example.com');
      client.clearCache();

      expect(mockDecryptedCapsaCacheClearAll).toHaveBeenCalled();
    });

    it('should destroy client and cleanup', async () => {
      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey('-----BEGIN PRIVATE KEY-----\nKey\n-----END PRIVATE KEY-----');

      await client.destroy();

      expect(mockDecryptedCapsaCacheClearAll).toHaveBeenCalled();
      expect(mockAuthServiceLogout).toHaveBeenCalled();
    });
  });

  describe('auth interceptor behavior', () => {
    it('should add auth header to requests', () => {
      mockAuthServiceGetToken.mockReturnValue('my-token');
      const client = new CapsaraClient('https://api.example.com');

      // Get the request interceptor
      const interceptor = mockAxios.requestInterceptors[0];
      const config = { headers: {} } as InternalAxiosRequestConfig;
      const result = interceptor!.onFulfilled(config);

      expect(result.headers.Authorization).toBe('Bearer my-token');
    });

    it('should not add auth header when no token', () => {
      mockAuthServiceGetToken.mockReturnValue(null);
      const client = new CapsaraClient('https://api.example.com');

      const interceptor = mockAxios.requestInterceptors[0];
      const config = { headers: {} } as InternalAxiosRequestConfig;
      const result = interceptor!.onFulfilled(config);

      expect(result.headers.Authorization).toBeUndefined();
    });

    it('should handle 401 with token refresh', async () => {
      mockAuthServiceCanRefresh.mockReturnValue(true);
      mockAuthServiceRefresh.mockResolvedValue(true);
      mockAuthServiceGetToken.mockReturnValue('new-token');

      // Create a callable mock axios
      const callableMockAxios = vi.fn().mockResolvedValue({ data: 'success' }) as unknown as typeof mockAxios;
      Object.assign(callableMockAxios, mockAxios);
      mockAxiosCreate.mockReturnValue(callableMockAxios);

      const client = new CapsaraClient('https://api.example.com');

      // Get the response interceptor from the callable mock
      const interceptors = (callableMockAxios as unknown as ReturnType<typeof createMockAxiosInstance>).responseInterceptors;
      const responseInterceptor = interceptors[0];
      const error = {
        response: { status: 401 },
        config: { headers: {} },
      };

      const result = await responseInterceptor!.onRejected!(error);

      expect(mockAuthServiceRefresh).toHaveBeenCalled();
      expect(result).toEqual({ data: 'success' });
    });

    it('should not refresh on 401 if canRefresh returns false', async () => {
      mockAuthServiceCanRefresh.mockReturnValue(false);

      const client = new CapsaraClient('https://api.example.com');

      const responseInterceptor = mockAxios.responseInterceptors[0];
      const error = new Error('401 Unauthorized');
      Object.assign(error, {
        response: { status: 401 },
        config: { headers: {} },
      });

      await expect(responseInterceptor!.onRejected!(error)).rejects.toBe(error);
      expect(mockAuthServiceRefresh).not.toHaveBeenCalled();
    });

    it('should bubble up refresh error', async () => {
      mockAuthServiceCanRefresh.mockReturnValue(true);
      mockAuthServiceRefresh.mockResolvedValue(false);
      const refreshError = new Error('Refresh failed');
      mockAuthServiceGetLastRefreshError.mockReturnValue(refreshError);

      const client = new CapsaraClient('https://api.example.com');

      const responseInterceptor = mockAxios.responseInterceptors[0];
      const error = {
        response: { status: 401 },
        config: { headers: {} },
      };

      await expect(responseInterceptor!.onRejected!(error)).rejects.toEqual(refreshError);
    });
  });
});
