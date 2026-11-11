/**
 * Tests for capsara-client.ts - Capsara SDK Client
 * @file tests/unit/client/capsara-client.test.ts
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AxiosInstance, InternalAxiosRequestConfig, AxiosResponse } from 'axios';
import type { SystemLimits, AuthResponse, EncryptedFile } from '../../../src/types/index.js';
import type { DecryptedCapsa } from '../../../src/internal/decryptor/capsa-decryptor.js';
import * as crypto from 'crypto';
import { rsa4096KeyPair } from '../../fixtures/rsa-keys.js';

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
    connectTimeout: 30000,
    keepAliveInterval: 30000,
    maxSockets: 50,
    maxFreeSockets: 10,
  },
}));

// Mock services
vi.mock('../../../src/internal/services/auth-service.js', () => ({
  AuthService: vi.fn().mockImplementation(function () {
    return {
      login: mockAuthServiceLogin,
      logout: mockAuthServiceLogout,
      getToken: mockAuthServiceGetToken,
      setToken: mockAuthServiceSetToken,
      isAuthenticated: mockAuthServiceIsAuthenticated,
      canRefresh: mockAuthServiceCanRefresh,
      refresh: mockAuthServiceRefresh,
      getLastRefreshError: mockAuthServiceGetLastRefreshError,
    };
  }),
}));

vi.mock('../../../src/internal/services/key-service.js', () => ({
  KeyManager: vi.fn().mockImplementation(function () {
    return {
      fetchPartyKeys: mockKeyManagerFetchPartyKeys,
    };
  }),
}));

vi.mock('../../../src/internal/services/limits-service.js', () => ({
  LimitsManager: vi.fn().mockImplementation(function () {
    return {
      getLimits: mockLimitsManagerGetLimits,
      clearCache: mockLimitsManagerClearCache,
    };
  }),
}));

vi.mock('../../../src/internal/services/account-service.js', () => ({
  AccountClient: vi.fn().mockImplementation(function () {
    return {
      getCurrentPublicKey: mockAccountClientGetCurrentPublicKey,
      addPublicKey: mockAccountClientAddPublicKey,
      getKeyHistory: mockAccountClientGetKeyHistory,
      rotateKey: mockAccountClientRotateKey,
    };
  }),
}));

vi.mock('../../../src/internal/services/capsa-service.js', () => ({
  CapsaService: vi.fn().mockImplementation(function () {
    return {
      getCapsa: mockCapsaServiceGetCapsa,
      getDecryptedCapsa: mockCapsaServiceGetDecryptedCapsa,
      listCapsas: mockCapsaServiceListCapsas,
      deleteCapsa: mockCapsaServiceDeleteCapsa,
    };
  }),
}));

vi.mock('../../../src/internal/services/download-service.js', () => ({
  DownloadService: vi.fn().mockImplementation(function () {
    return {
      downloadAndDecryptFile: mockDownloadServiceDownloadAndDecryptFile,
    };
  }),
}));

vi.mock('../../../src/internal/services/upload-service.js', () => ({
  UploadService: vi.fn().mockImplementation(function () {
    return {
      sendCapsas: mockUploadServiceSendCapsas,
    };
  }),
}));

vi.mock('../../../src/internal/services/audit-service.js', () => ({
  AuditService: vi.fn().mockImplementation(function () {
    return {
      getAuditEntries: mockAuditServiceGetAuditEntries,
      createAuditEntry: mockAuditServiceCreateAuditEntry,
    };
  }),
}));

vi.mock('../../../src/internal/capsa-cache.js', () => ({
  DecryptedCapsaCache: vi.fn().mockImplementation(function () {
    return {
      set: mockDecryptedCapsaCacheSet,
      clear: mockDecryptedCapsaCacheClear,
      clearAll: mockDecryptedCapsaCacheClearAll,
      getMasterKey: mockDecryptedCapsaCacheGetMasterKey,
      getFileMetadata: mockDecryptedCapsaCacheGetFileMetadata,
    };
  }),
}));

vi.mock('../../../src/internal/crypto/key-generator.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/internal/crypto/key-generator.js')>()),
  generateKeyPair: mockGenerateKeyPair,
}));

vi.mock('../../../src/builder/capsa-builder.js', () => ({
  CapsaBuilder: vi.fn().mockImplementation(function (creatorId, privateKey, limits) {
    return {
      creatorId,
      privateKey,
      limits,
      addRecipient: vi.fn().mockReturnThis(),
      addFile: vi.fn().mockReturnThis(),
      getRecipientIds: vi.fn().mockReturnValue([]),
    };
  }),
}));

import { CapsaraClient, type CapsaraClientOptions } from '../../../src/client/capsara-client.js';
import { CapsaraAuthError } from '../../../src/errors/auth-error.js';
import { CapsaraCapsaError } from '../../../src/errors/capsa-error.js';

function createEncryptedFile(overrides: Partial<EncryptedFile> = {}): EncryptedFile {
  return {
    fileId: 'file_001',
    encryptedFilename: 'name',
    filenameIV: 'fiv',
    filenameAuthTag: 'ftag',
    iv: 'iv',
    authTag: 'tag',
    mimetype: 'text/plain',
    size: 100,
    hash: 'hash',
    hashAlgorithm: 'SHA-256',
    ...overrides,
  };
}

function createDecryptedCapsa(overrides: Partial<DecryptedCapsa> = {}): DecryptedCapsa {
  const signature = { algorithm: 'RS256', protected: 'protected', payload: 'payload', signature: 'signature' };
  const keychain = { algorithm: 'RSA-OAEP-SHA256', keys: [] };
  return {
    id: 'capsa_123',
    creator: 'party_123',
    createdAt: '2024-01-15T10:30:00Z',
    updatedAt: '2024-01-15T10:30:00Z',
    status: 'active',
    files: [],
    accessControl: {},
    _masterKey: Buffer.from('master-key-bytes'),
    clearMasterKey: vi.fn(),
    keychain,
    signature,
    stats: { totalSize: 0, fileCount: 0 },
    _encrypted: {
      id: 'capsa_123',
      createdAt: '2024-01-15T10:30:00Z',
      updatedAt: '2024-01-15T10:30:00Z',
      status: 'active',
      creator: 'party_123',
      signature,
      keychain,
      files: [],
      accessControl: {},
      totalSize: 0,
    },
    ...overrides,
  };
}

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

    it('should not log in from constructor options (login is explicit)', async () => {
      const options = {
        credentials: { partyId: 'party_abcdefghijklmnopqrstu', password: 'secret' },
      } as unknown as CapsaraClientOptions;

      new CapsaraClient('https://api.example.com', options);

      await new Promise(resolve => setTimeout(resolve, 10));
      expect(mockAuthServiceLogin).not.toHaveBeenCalled();
    });

    it('should set access token when provided', () => {
      new CapsaraClient('https://api.example.com', {
        accessToken: 'pre-existing-token',
      });

      expect(mockAuthServiceSetToken).toHaveBeenCalledWith('pre-existing-token');
    });

    it('should configure auth request interceptor', () => {
      new CapsaraClient('https://api.example.com');
      expect(mockAxios.interceptors.request.use).toHaveBeenCalled();
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
      const result = await client.login({ partyId: 'party_abcdefghijklmnopqrstu', password: 'secret' });

      expect(result).toEqual(authResponse);
      expect(mockAuthServiceLogin).toHaveBeenCalledWith({ partyId: 'party_abcdefghijklmnopqrstu', password: 'secret' });
    });

    it('should logout and clear cache', async () => {
      const client = new CapsaraClient('https://api.example.com');
      const result = await client.logout();

      expect(result).toBe(true);
      expect(mockDecryptedCapsaCacheClearAll).toHaveBeenCalled();
      expect(mockAuthServiceLogout).toHaveBeenCalled();
    });

    it('should clear the cache and surface a failed server logout', async () => {
      const failure = new CapsaraAuthError('Failed to logout', 'LOGOUT_FAILED', 500);
      mockAuthServiceLogout.mockRejectedValueOnce(failure);
      const client = new CapsaraClient('https://api.example.com');

      await expect(client.logout()).rejects.toBe(failure);
      expect(mockDecryptedCapsaCacheClearAll).toHaveBeenCalled();
    });

    it('should not throw from destroy when the server logout fails', async () => {
      mockAuthServiceLogout.mockRejectedValueOnce(new CapsaraAuthError('Failed to logout', 'LOGOUT_FAILED', 500));
      const client = new CapsaraClient('https://api.example.com');

      await expect(client.destroy()).resolves.toBeUndefined();
    });

    it('should check authentication status', () => {
      mockAuthServiceIsAuthenticated.mockReturnValue(true);

      const client = new CapsaraClient('https://api.example.com');
      expect(client.isAuthenticated()).toBe(true);
    });

    it('should set private key', () => {
      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey(rsa4096KeyPair(0).privateKey);
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
      await client.login({ partyId: 'party_abcdefghijklmnopqrstu', password: 'secret' });
      client.setPrivateKey(rsa4096KeyPair(0).privateKey);

      const builder = await client.createCapsaBuilder();

      expect(mockLimitsManagerGetLimits).toHaveBeenCalled();
      expect(builder).toBeDefined();
    });

    it('should throw if creating builder without identity', async () => {
      const client = new CapsaraClient('https://api.example.com');

      await expect(client.createCapsaBuilder()).rejects.toMatchObject({
        name: 'CapsaraError',
        code: 'NOT_LOGGED_IN',
        statusCode: 0,
        message: 'Creator identity not set. Call login() first.',
      });
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
      await client.login({ partyId: 'party_abcdefghijklmnopqrstu', password: 'secret' });
      client.setPrivateKey(rsa4096KeyPair(0).privateKey);

      const result = await client.sendCapsas([]);

      expect(result).toEqual(sendResult);
    });

    it('should throw if sending without identity', async () => {
      const client = new CapsaraClient('https://api.example.com');

      await expect(client.sendCapsas([])).rejects.toMatchObject({ code: 'NOT_LOGGED_IN', statusCode: 0 });
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
      const decrypted = createDecryptedCapsa();
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decrypted);

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey(rsa4096KeyPair(0).privateKey);

      const result = await client.getCapsa('capsa_123');

      expect(result).toEqual(decrypted);
      expect(mockDecryptedCapsaCacheSet).toHaveBeenCalled();
    });

    it('should throw if decrypting without identity', async () => {
      const client = new CapsaraClient('https://api.example.com');

      await expect(client.getCapsa('capsa_123')).rejects.toMatchObject({
        name: 'CapsaraError',
        code: 'MISSING_PRIVATE_KEY',
        statusCode: 0,
        message: 'Private key required. Call setPrivateKey() first.',
      });
    });

    it('should throw MISSING_PRIVATE_KEY when creating a builder after login without a private key', async () => {
      const client = new CapsaraClient('https://api.example.com');
      (client as unknown as { creatorId: string }).creatorId = 'party_self';

      await expect(client.createCapsaBuilder()).rejects.toMatchObject({ code: 'MISSING_PRIVATE_KEY', statusCode: 0 });
    });

    it('should deduplicate concurrent getCapsa requests', async () => {
      const decrypted = createDecryptedCapsa();
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decrypted);

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey(rsa4096KeyPair(0).privateKey);

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

      const decrypted = createDecryptedCapsa({ files: [createEncryptedFile()] });
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decrypted);
      mockDownloadServiceDownloadAndDecryptFile.mockResolvedValue({
        data: Buffer.from('content'),
        filename: 'test.txt',
      });

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey(rsa4096KeyPair(0).privateKey);

      const result = await client.downloadFile('capsa_123', 'file_001');

      expect(mockCapsaServiceGetDecryptedCapsa).toHaveBeenCalled();
      expect(result.filename).toBe('test.txt');
    });

    const fileMetadata = { iv: 'iv', authTag: 'tag', encryptedFilename: 'name', filenameIV: 'fiv', filenameAuthTag: 'ftag' };

    it('should decrypt with its own copy of the cached master key and zero it afterwards', async () => {
      const cachedKey = Buffer.alloc(32, 7);
      mockDecryptedCapsaCacheGetMasterKey.mockReturnValue(cachedKey);
      mockDecryptedCapsaCacheGetFileMetadata.mockReturnValue(fileMetadata);
      let usedKey: Buffer | undefined;
      let keyDuringDownload: Buffer | undefined;
      mockDownloadServiceDownloadAndDecryptFile.mockImplementation(async (_c: string, _f: string, key: Buffer) => {
        usedKey = key;
        keyDuringDownload = Buffer.from(key);
        cachedKey.fill(0);
        return { data: Buffer.from('content'), filename: 'a.txt' };
      });

      await new CapsaraClient('https://api.example.com').downloadFile('capsa_123', 'file_001');

      expect(usedKey).not.toBe(cachedKey);
      expect(keyDuringDownload).toEqual(Buffer.alloc(32, 7));
      expect(usedKey).toEqual(Buffer.alloc(32, 0));
    });

    it('should zero its master key copy when the download fails', async () => {
      const cachedKey = Buffer.alloc(32, 9);
      mockDecryptedCapsaCacheGetMasterKey.mockReturnValue(cachedKey);
      mockDecryptedCapsaCacheGetFileMetadata.mockReturnValue(fileMetadata);
      let usedKey: Buffer | undefined;
      mockDownloadServiceDownloadAndDecryptFile.mockImplementation(async (_c: string, _f: string, key: Buffer) => {
        usedKey = key;
        throw new Error('blob unavailable');
      });

      await expect(new CapsaraClient('https://api.example.com').downloadFile('capsa_123', 'file_001')).rejects.toThrow('blob unavailable');

      expect(usedKey).toEqual(Buffer.alloc(32, 0));
      expect(cachedKey).toEqual(Buffer.alloc(32, 9));
    });

    it('should throw if file not found in capsa', async () => {
      mockDecryptedCapsaCacheGetMasterKey.mockReturnValue(null);
      mockDecryptedCapsaCacheGetFileMetadata.mockReturnValue(null);

      const decrypted = createDecryptedCapsa();
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decrypted);

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey(rsa4096KeyPair(0).privateKey);

      const error = await client.downloadFile('capsa_123', 'file_missing').catch((e: unknown) => e);

      expect(error).toBeInstanceOf(CapsaraCapsaError);
      expect(error).toMatchObject({
        code: 'FILE_NOT_FOUND',
        statusCode: 0,
        details: { capsaId: 'capsa_123', fileId: 'file_missing' },
        message: 'File file_missing not found in capsa capsa_123',
      });
    });
  });

  describe('audit operations', () => {
    it('should get audit entries', async () => {
      const response = {
        auditEntries: [],
        pagination: { page: 1, limit: 100, total: 0, totalPages: 0 },
      };
      mockAuditServiceGetAuditEntries.mockResolvedValue(response);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.getAuditEntries('capsa_123');

      expect(result).toEqual(response);
    });

    it('should create audit entry', async () => {
      const response = { success: true, message: 'Created' };
      mockAuditServiceCreateAuditEntry.mockResolvedValue(response);

      const client = new CapsaraClient('https://api.example.com');
      const result = await client.createAuditEntry('capsa_123', { action: 'log' });

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
      const history = [{ keyFingerprint: 'fp', rotatedAt: '2024-01-01T00:00:00Z', rotatedBy: 'party_a', envelopesAffected: 2 }];
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
      client.setPrivateKey(rsa4096KeyPair(0).privateKey);

      await client.destroy();

      expect(mockDecryptedCapsaCacheClearAll).toHaveBeenCalled();
      expect(mockAuthServiceLogout).toHaveBeenCalled();
    });
  });

  describe('previous private keys', () => {
    function makePrivateKey(): string {
      return crypto.generateKeyPairSync('rsa', {
        modulusLength: 1024,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      }).privateKey;
    }

    const currentKey = makePrivateKey();
    const oldKey = makePrivateKey();
    const olderKey = makePrivateKey();

    function decryptedStub() {
      return { id: 'capsa_123', files: [], _masterKey: Buffer.alloc(32) };
    }

    it('passes the caller party ID and previous keys from options to decryption', async () => {
      mockAuthServiceLogin.mockResolvedValue({
        party: { id: 'party_me', email: 'e', name: 'n', kind: 'organization' },
        accessToken: 't',
        refreshToken: 'r',
        expiresIn: 3600,
      });
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decryptedStub());

      const client = new CapsaraClient('https://api.example.com', { previousPrivateKeys: [oldKey] });
      await client.login({ partyId: 'party_me', password: 'p' });
      client.setPrivateKey(currentKey);
      client.addPreviousPrivateKey(olderKey);

      await client.getCapsa('capsa_123');

      expect(mockCapsaServiceGetDecryptedCapsa).toHaveBeenCalledWith('capsa_123', currentKey, {
        partyId: 'party_me',
        previousPrivateKeys: [oldKey, olderKey],
      });
    });

    it('omits the party ID when the client only has an access token', async () => {
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decryptedStub());

      const client = new CapsaraClient('https://api.example.com', { accessToken: 'token' });
      client.setPrivateKey(currentKey);

      await client.getCapsa('capsa_123');

      expect(mockCapsaServiceGetDecryptedCapsa).toHaveBeenCalledWith('capsa_123', currentKey, { previousPrivateKeys: [] });
    });

    it('ignores a duplicate previous key', async () => {
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decryptedStub());

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey(currentKey);
      client.addPreviousPrivateKey(oldKey);
      client.addPreviousPrivateKey(oldKey);

      await client.getCapsa('capsa_123');

      expect(mockCapsaServiceGetDecryptedCapsa.mock.calls[0]?.[2]).toEqual({ previousPrivateKeys: [oldKey] });
    });

    const invalidKey = expect.objectContaining({ code: 'INVALID_PRIVATE_KEY', statusCode: 0 });

    it('rejects an invalid previous key and keeps the existing ones', async () => {
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decryptedStub());
      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey(currentKey);
      client.addPreviousPrivateKey(oldKey);

      expect(() => client.addPreviousPrivateKey('not a key')).toThrow(invalidKey);
      expect(() => client.addPreviousPrivateKey('not a key')).toThrow('The previous private key is not a usable RSA private key PEM.');
      await client.getCapsa('capsa_123');

      expect(mockCapsaServiceGetDecryptedCapsa.mock.calls[0]?.[2]).toEqual({ previousPrivateKeys: [oldKey] });
    });

    it('rejects an invalid previous key passed in options', () => {
      expect(() => new CapsaraClient('https://api.example.com', { previousPrivateKeys: ['nope'] })).toThrow(invalidKey);
    });

    it('rejects an invalid current key and keeps the one already set', async () => {
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decryptedStub());
      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey(currentKey);

      expect(() => client.setPrivateKey('-----BEGIN PRIVATE KEY-----\nKey\n-----END PRIVATE KEY-----')).toThrow(invalidKey);
      expect(() => client.setPrivateKey('')).toThrow('The current private key is not a usable RSA private key PEM.');
      await client.getCapsa('capsa_123');

      expect(mockCapsaServiceGetDecryptedCapsa).toHaveBeenCalledWith('capsa_123', currentKey, { previousPrivateKeys: [] });
    });

    it('rejects a private key that is not RSA', () => {
      const ecKey = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      }).privateKey;
      const client = new CapsaraClient('https://api.example.com');

      expect(() => client.setPrivateKey(ecKey)).toThrow(invalidKey);
      expect(() => client.addPreviousPrivateKey(ecKey)).toThrow(invalidKey);
    });

    function rotation(privateKey: string) {
      return {
        keyPair: { publicKey: 'pub', privateKey, publicKeyFingerprint: 'fp' },
        serverInfo: { publicKey: 'pub', keyFingerprint: 'fp', createdAt: '2024-01-01', isActive: true },
      };
    }

    it('switches to the rotated key and keeps the old one as a previous key', async () => {
      mockAccountClientRotateKey.mockResolvedValue(rotation(currentKey));
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decryptedStub());

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey(oldKey);
      await client.rotateKey();
      await client.getCapsa('capsa_123');

      expect(mockCapsaServiceGetDecryptedCapsa).toHaveBeenCalledWith('capsa_123', currentKey, { previousPrivateKeys: [oldKey] });
      expect(mockDecryptedCapsaCacheClearAll).toHaveBeenCalled();
    });

    it('passes rotation options through to the account client', async () => {
      mockAccountClientRotateKey.mockResolvedValue(rotation(currentKey));
      const onKeyPairGenerated = vi.fn();

      await new CapsaraClient('https://api.example.com').rotateKey({ onKeyPairGenerated, reason: 'scheduled' });

      expect(mockAccountClientRotateKey).toHaveBeenCalledWith({ onKeyPairGenerated, reason: 'scheduled' });
    });

    it('sets the rotated key without a previous key when none was set', async () => {
      mockAccountClientRotateKey.mockResolvedValue(rotation(currentKey));
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decryptedStub());

      const client = new CapsaraClient('https://api.example.com');
      await client.rotateKey();
      await client.getCapsa('capsa_123');

      expect(mockCapsaServiceGetDecryptedCapsa).toHaveBeenCalledWith('capsa_123', currentKey, { previousPrivateKeys: [] });
    });

    it('keeps the current key when registering the new key fails', async () => {
      mockAccountClientRotateKey.mockRejectedValue(new Error('Key registration failed'));
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decryptedStub());

      const client = new CapsaraClient('https://api.example.com');
      client.setPrivateKey(oldKey);
      await expect(client.rotateKey()).rejects.toThrow('Key registration failed');
      await client.getCapsa('capsa_123');

      expect(mockCapsaServiceGetDecryptedCapsa).toHaveBeenCalledWith('capsa_123', oldKey, { previousPrivateKeys: [] });
    });

    it('forgets previous keys on destroy', async () => {
      mockCapsaServiceGetDecryptedCapsa.mockResolvedValue(decryptedStub());

      const client = new CapsaraClient('https://api.example.com', { previousPrivateKeys: [oldKey] });
      await client.destroy();
      client.setPrivateKey(currentKey);
      await client.getCapsa('capsa_123');

      expect(mockCapsaServiceGetDecryptedCapsa.mock.calls[0]?.[2]).toEqual({ previousPrivateKeys: [] });
    });
  });

  describe('auth interceptor behavior', () => {
    it('should add auth header to requests', () => {
      mockAuthServiceGetToken.mockReturnValue('my-token');
      new CapsaraClient('https://api.example.com');

      // Get the request interceptor
      const interceptor = mockAxios.requestInterceptors[0];
      const config = { headers: {} } as InternalAxiosRequestConfig;
      const result = interceptor!.onFulfilled(config);

      expect(result.headers.Authorization).toBe('Bearer my-token');
    });

    it('should not add auth header when no token', () => {
      mockAuthServiceGetToken.mockReturnValue(null);
      new CapsaraClient('https://api.example.com');

      const interceptor = mockAxios.requestInterceptors[0];
      const config = { headers: {} } as InternalAxiosRequestConfig;
      const result = interceptor!.onFulfilled(config);

      expect(result.headers.Authorization).toBeUndefined();
    });
  });
});
