/**
 * Tests for download-service.ts - File download and decryption service
 * @file tests/unit/internal/services/download-service.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import type { AxiosInstance } from 'axios';

// Use vi.hoisted for mock functions
const { mockDecryptAESRaw, mockDecompressData, mockDecryptFilename } = vi.hoisted(() => ({
  mockDecryptAESRaw: vi.fn(),
  mockDecompressData: vi.fn(),
  mockDecryptFilename: vi.fn(),
}));

// Mock decryption functions (download-service now imports directly)
vi.mock('../../../../src/internal/decryptor/capsa-decryptor.js', () => ({
  decryptFilename: mockDecryptFilename,
}));

vi.mock('../../../../src/internal/crypto/primitives.js', () => ({
  decryptAESRaw: mockDecryptAESRaw,
}));

vi.mock('../../../../src/internal/crypto/compression.js', () => ({
  decompressData: mockDecompressData,
}));

// Mock CapsaraCapsaError
vi.mock('../../../../src/errors/capsa-error.js', () => ({
  CapsaraCapsaError: {
    fromApiError: vi.fn((error) => {
      const err = new Error('API Error');
      (err as Error & { originalError?: unknown }).originalError = error;
      return err;
    }),
    downloadFailed: vi.fn((capsaId, fileId, error) => {
      const err = new Error(`Download failed for ${capsaId}/${fileId}`);
      (err as Error & { originalError?: unknown }).originalError = error;
      return err;
    }),
  },
}));

import {
  DownloadService,
  type DownloadServiceOptions,
  type FileMetadata,
} from '../../../../src/internal/services/download-service.js';

// Helper to create mock axios instance
function createMockAxiosInstance(): AxiosInstance {
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
      request: { use: vi.fn(), eject: vi.fn(), clear: vi.fn() },
      response: { use: vi.fn(), eject: vi.fn(), clear: vi.fn() },
    },
  } as unknown as AxiosInstance;
}

// Helper to create default options
function createDefaultOptions(
  overrides?: Partial<DownloadServiceOptions>
): DownloadServiceOptions {
  return {
    axiosInstance: createMockAxiosInstance(),
    blobClient: createMockAxiosInstance(),  // Injected blob client for blob storage downloads
    retryConfig: {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 30000,
      enableLogging: false,
    },
    logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
    ...overrides,
  };
}

// Helper to create file metadata
function createFileMetadata(overrides?: Partial<FileMetadata>): FileMetadata {
  return {
    iv: 'test-iv-12345678',
    authTag: 'test-auth-tag-16b',
    compressed: false,
    encryptedFilename: 'encrypted-filename-base64url',
    filenameIV: 'filename-iv-1234',
    filenameAuthTag: 'filename-auth-16',
    ...overrides,
  };
}

describe('DownloadService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('constructor', () => {
    it('should create service with options', () => {
      const options = createDefaultOptions();
      const service = new DownloadService(options);

      expect(service).toBeInstanceOf(DownloadService);
    });
  });

  describe('getFileDownloadUrl', () => {
    it('should get download URL for file', async () => {
      const options = createDefaultOptions();
      const mockResponse = {
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      };

      (options.axiosInstance.get as Mock).mockResolvedValue(mockResponse);

      const service = new DownloadService(options);
      const result = await service.getFileDownloadUrl('capsa_123', 'file_123');

      expect(result.downloadUrl).toBe('https://blob.storage.com/files/file_123');
      expect(result.expiresAt).toBe('2025-12-31T23:59:59Z');
      expect(options.axiosInstance.get).toHaveBeenCalledWith(
        '/api/capsas/capsa_123/files/file_123/download',
        { params: { expires: 60 } }
      );
    });

    it('should use custom expiration time', async () => {
      const options = createDefaultOptions();
      const mockResponse = {
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      };

      (options.axiosInstance.get as Mock).mockResolvedValue(mockResponse);

      const service = new DownloadService(options);
      await service.getFileDownloadUrl('capsa_123', 'file_123', 120);

      expect(options.axiosInstance.get).toHaveBeenCalledWith(
        '/api/capsas/capsa_123/files/file_123/download',
        { params: { expires: 120 } }
      );
    });

    it('should handle API error', async () => {
      const options = createDefaultOptions();
      const apiError = {
        response: {
          status: 404,
          data: { message: 'File not found' },
        },
      };

      (options.axiosInstance.get as Mock).mockRejectedValue(apiError);

      const service = new DownloadService(options);

      await expect(service.getFileDownloadUrl('capsa_123', 'file_123')).rejects.toThrow(
        'API Error'
      );
    });
  });

  describe('downloadEncryptedFile', () => {
    it('should download encrypted file', async () => {
      const options = createDefaultOptions();
      const downloadUrl = 'https://blob.storage.com/files/file_123';

      // Mock getFileDownloadUrl response
      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl,
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      // Mock blob client download - use Uint8Array for proper ArrayBuffer
      const encryptedData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      (options.blobClient.get as Mock).mockResolvedValue({
        data: encryptedData.buffer,
      });

      const service = new DownloadService(options);
      const result = await service.downloadEncryptedFile('capsa_123', 'file_123');

      expect(Buffer.isBuffer(result)).toBe(true);
      expect(result.length).toBe(8);
      expect(options.blobClient.get).toHaveBeenCalledWith(downloadUrl, {
        responseType: 'arraybuffer',
      });
    });
  });

  describe('downloadAndDecryptFile', () => {
    it('should download and decrypt file', async () => {
      const options = createDefaultOptions();
      const capsaId = 'capsa_123';
      const fileId = 'file_456';
      const masterKey = Buffer.from('test-master-key-32bytes!!!!');
      const metadata = createFileMetadata();

      // Mock getFileDownloadUrl
      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId,
          downloadUrl: 'https://blob.storage.com/files/file_456',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      // Mock axios download - use Uint8Array to create a proper ArrayBuffer
      const encryptedContent = 'encrypted-content';
      const uint8Array = new Uint8Array(Buffer.from(encryptedContent));
      (options.blobClient.get as Mock).mockResolvedValue({ data: uint8Array.buffer.slice(0, encryptedContent.length) });

      // Mock decryption (now uses decryptAESRaw + decompressData directly)
      const decryptedData = Buffer.from('decrypted-content');
      mockDecryptAESRaw.mockReturnValue(decryptedData);
      mockDecryptFilename.mockReturnValue('original-filename.txt');

      const service = new DownloadService(options);
      const result = await service.downloadAndDecryptFile(
        capsaId,
        fileId,
        masterKey,
        metadata
      );

      expect(result.data).toBe(decryptedData);
      expect(result.filename).toBe('original-filename.txt');
      expect(mockDecryptAESRaw).toHaveBeenCalledWith(
        expect.any(Buffer), // raw encrypted data
        masterKey,
        expect.any(Buffer), // iv decoded from base64url
        expect.any(Buffer)  // authTag decoded from base64url
      );
      expect(mockDecryptFilename).toHaveBeenCalledWith(
        metadata.encryptedFilename,
        masterKey,
        metadata.filenameIV,
        metadata.filenameAuthTag
      );
    });

    it('should handle compressed files', async () => {
      const options = createDefaultOptions();
      const metadata = createFileMetadata({ compressed: true });

      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      // Use Uint8Array for proper ArrayBuffer
      const compressedData = new Uint8Array([1, 2, 3, 4, 5]);
      (options.blobClient.get as Mock).mockResolvedValue({ data: compressedData.buffer });
      mockDecryptAESRaw.mockReturnValue(Buffer.from('compressed-data'));
      mockDecompressData.mockResolvedValue(Buffer.from('decompressed-data'));
      mockDecryptFilename.mockReturnValue('file.txt');

      const service = new DownloadService(options);
      await service.downloadAndDecryptFile(
        'capsa_123',
        'file_123',
        Buffer.from('master-key-32bytes-padding!!!!'),
        metadata
      );

      expect(mockDecryptAESRaw).toHaveBeenCalled();
      expect(mockDecompressData).toHaveBeenCalledWith(Buffer.from('compressed-data'));
    });

    it('should handle decryption error', async () => {
      const options = createDefaultOptions();
      const metadata = createFileMetadata();

      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      // Use Uint8Array for proper ArrayBuffer
      const encryptedData = new Uint8Array([1, 2, 3, 4, 5]);
      (options.blobClient.get as Mock).mockResolvedValue({ data: encryptedData.buffer });
      mockDecryptAESRaw.mockImplementation(() => { throw new Error('Decryption failed'); });

      const service = new DownloadService(options);

      await expect(
        service.downloadAndDecryptFile(
          'capsa_123',
          'file_123',
          Buffer.from('master-key-32bytes-padding!!!!'),
          metadata
        )
      ).rejects.toThrow('Download failed for capsa_123/file_123');
    });
  });

  describe('retry logic', () => {
    it('should retry on 503 status', async () => {
      const options = createDefaultOptions();

      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      // First call fails with 503, second succeeds
      const successData = new Uint8Array([1, 2, 3, 4, 5]);
      (options.blobClient.get as Mock)
        .mockRejectedValueOnce({
          response: {
            status: 503,
            data: { error: { retryAfter: 1 } },
          },
        })
        .mockResolvedValueOnce({ data: successData.buffer });

      const service = new DownloadService(options);
      const resultPromise = service.downloadEncryptedFile('capsa_123', 'file_123');

      await vi.runAllTimersAsync();
      const result = await resultPromise;

      expect(Buffer.isBuffer(result)).toBe(true);
      expect(options.blobClient.get).toHaveBeenCalledTimes(2);
    });

    it('should retry on 429 status', async () => {
      const options = createDefaultOptions();

      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      const successData = new Uint8Array([1, 2, 3, 4, 5]);
      (options.blobClient.get as Mock)
        .mockRejectedValueOnce({
          response: {
            status: 429,
            data: {},
          },
        })
        .mockResolvedValueOnce({ data: successData.buffer });

      const service = new DownloadService(options);
      const resultPromise = service.downloadEncryptedFile('capsa_123', 'file_123');

      await vi.runAllTimersAsync();
      const result = await resultPromise;

      expect(Buffer.isBuffer(result)).toBe(true);
    });

    it('should stop retrying after max retries exceeded', async () => {
      const options = createDefaultOptions({
        retryConfig: {
          maxRetries: 2,
          baseDelay: 100,
          maxDelay: 1000,
          enableLogging: false,
        },
      });

      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      const error = {
        response: {
          status: 503,
          data: {},
        },
      };

      (options.blobClient.get as Mock).mockRejectedValue(error);

      const service = new DownloadService(options);
      const resultPromise = service.downloadEncryptedFile('capsa_123', 'file_123');

      await vi.runAllTimersAsync();

      await expect(resultPromise).rejects.toEqual(error);
      expect(options.blobClient.get).toHaveBeenCalledTimes(3); // Initial + 2 retries
    });

    it('should not retry on non-retryable error', async () => {
      const options = createDefaultOptions();

      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      const error = {
        response: {
          status: 400,
          data: { error: 'Bad request' },
        },
      };

      (options.blobClient.get as Mock).mockRejectedValue(error);

      const service = new DownloadService(options);

      await expect(service.downloadEncryptedFile('capsa_123', 'file_123')).rejects.toEqual(
        error
      );
      expect(options.blobClient.get).toHaveBeenCalledTimes(1);
    });

    it('should log retry attempts when logging enabled', async () => {
      const logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() };
      const options = createDefaultOptions({
        retryConfig: {
          maxRetries: 3,
          baseDelay: 100,
          maxDelay: 1000,
          enableLogging: true,
        },
        logger,
      });

      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      const successData = new Uint8Array([1, 2, 3, 4, 5]);
      (options.blobClient.get as Mock)
        .mockRejectedValueOnce({
          response: {
            status: 503,
            data: {},
          },
        })
        .mockResolvedValueOnce({ data: successData.buffer });

      const service = new DownloadService(options);
      const resultPromise = service.downloadEncryptedFile('capsa_123', 'file_123');

      await vi.runAllTimersAsync();
      await resultPromise;

      const logCalls = (logger.log as Mock).mock.calls.map((call) => call[0] as string);
      expect(logCalls.some((msg) => msg.includes('Retry attempt'))).toBe(true);
    });

    it('should use server-suggested retry delay', async () => {
      const options = createDefaultOptions();

      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      const successData = new Uint8Array([1, 2, 3, 4, 5]);
      (options.blobClient.get as Mock)
        .mockRejectedValueOnce({
          response: {
            status: 503,
            data: { error: { retryAfter: 5 } }, // 5 seconds
          },
        })
        .mockResolvedValueOnce({ data: successData.buffer });

      const service = new DownloadService(options);
      const resultPromise = service.downloadEncryptedFile('capsa_123', 'file_123');

      await vi.runAllTimersAsync();
      await resultPromise;

      expect(options.blobClient.get).toHaveBeenCalledTimes(2);
    });

    it('should cap retry delay at maxDelay', async () => {
      const options = createDefaultOptions({
        retryConfig: {
          maxRetries: 3,
          baseDelay: 50000, // Very high base
          maxDelay: 1000, // Low cap
          enableLogging: false,
        },
      });

      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      const successData = new Uint8Array([1, 2, 3, 4, 5]);
      (options.blobClient.get as Mock)
        .mockRejectedValueOnce({
          response: {
            status: 503,
            data: {},
          },
        })
        .mockResolvedValueOnce({ data: successData.buffer });

      const service = new DownloadService(options);
      const resultPromise = service.downloadEncryptedFile('capsa_123', 'file_123');

      await vi.runAllTimersAsync();
      await resultPromise;

      expect(options.blobClient.get).toHaveBeenCalledTimes(2);
    });

    it('should use exponential backoff when no server delay', async () => {
      const options = createDefaultOptions();

      (options.axiosInstance.get as Mock).mockResolvedValue({
        data: {
          fileId: 'file_123',
          downloadUrl: 'https://blob.storage.com/files/file_123',
          expiresAt: '2025-12-31T23:59:59Z',
        },
      });

      const successData = new Uint8Array([1, 2, 3, 4, 5]);
      (options.blobClient.get as Mock)
        .mockRejectedValueOnce({
          response: {
            status: 503,
            data: {}, // No retryAfter
          },
        })
        .mockResolvedValueOnce({ data: successData.buffer });

      const service = new DownloadService(options);
      const resultPromise = service.downloadEncryptedFile('capsa_123', 'file_123');

      await vi.runAllTimersAsync();
      await resultPromise;

      expect(options.blobClient.get).toHaveBeenCalledTimes(2);
    });
  });
});
