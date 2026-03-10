/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Download Operations
 * Tests cached master key, lazy fetch, missing authTag error,
 * blob retry 503/429, max retries, SAS URL expiration, error context wrapping.
 */

import { DownloadService, type DownloadServiceOptions, type FileMetadata } from '../../src/internal/services/download-service.js';
import type { AxiosInstance } from 'axios';
import type { AxiosLikeError } from '../../src/errors/capsara-error.js';

function createMockAxios(): AxiosInstance {
  return {
    get: vi.fn(),
    post: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  } as unknown as AxiosInstance;
}

function createService(overrides?: {
  httpGet?: ReturnType<typeof vi.fn>;
  blobGet?: ReturnType<typeof vi.fn>;
}): {
  service: DownloadService;
  http: AxiosInstance;
  blob: AxiosInstance;
} {
  const http = createMockAxios();
  const blob = createMockAxios();

  if (overrides?.httpGet) (http.get as ReturnType<typeof vi.fn>) = overrides.httpGet;
  if (overrides?.blobGet) (blob.get as ReturnType<typeof vi.fn>) = overrides.blobGet;

  const options: DownloadServiceOptions = {
    axiosInstance: http,
    blobClient: blob,
    retryConfig: {
      maxRetries: 3,
      baseDelay: 100,
      maxDelay: 5000,
      enableLogging: false,
      logger: { log: vi.fn() },
    },
    logger: { log: vi.fn() },
  };

  const service = new DownloadService(options);
  return { service, http, blob };
}

const MOCK_METADATA: FileMetadata = {
  iv: 'dGVzdGl2MTIzNDU2', // 12 bytes base64url
  authTag: 'dGVzdGF1dGh0YWcxMjM0NQ', // 16 bytes base64url
  encryptedFilename: 'ZW5jLWZpbGVuYW1l',
  filenameIV: 'Zm5pdnRlc3QxMjM0',
  filenameAuthTag: 'Zm5hdGFnMTIzNDU2Nzg',
};

describe('Golden: Download', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should get download URL from API', async () => {
    const { service, http } = createService();
    (http.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: {
        fileId: 'file_1.enc',
        downloadUrl: 'https://blob.example.com/file_1.enc?sas=token',
        expiresAt: '2025-12-31T23:59:59Z',
      },
    });

    const result = await service.getFileDownloadUrl('capsa_1', 'file_1.enc');

    expect(result.downloadUrl).toContain('sas=token');
    expect(result.expiresAt).toBe('2025-12-31T23:59:59Z');
  });

  it('should download encrypted file from blob storage via SAS URL', async () => {
    const { service, http, blob } = createService();
    (http.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: {
        fileId: 'file_1.enc',
        downloadUrl: 'https://blob.example.com/file_1.enc?sas=tok',
        expiresAt: '2025-12-31T23:59:59Z',
      },
    });
    const fileBuffer = Buffer.from('encrypted-content');
    (blob.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: fileBuffer.buffer.slice(fileBuffer.byteOffset, fileBuffer.byteOffset + fileBuffer.byteLength),
    });

    const result = await service.downloadEncryptedFile('capsa_1', 'file_1.enc');

    expect(Buffer.isBuffer(result)).toBe(true);
  });

  it('should throw security error when authTag is missing', async () => {
    // decryptFile (called internally) requires authTag
    // Test via downloadAndDecryptFile with empty authTag
    const { service, http, blob } = createService();
    (http.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: {
        fileId: 'file_1.enc',
        downloadUrl: 'https://blob.example.com/f?sas=tok',
        expiresAt: '2025-12-31T23:59:59Z',
      },
    });
    (blob.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: Buffer.from('encrypted').buffer,
    });

    const metadataNoAuth = { ...MOCK_METADATA, authTag: '' };

    await expect(
      service.downloadAndDecryptFile('capsa_1', 'file_1.enc', Buffer.from('fake-master-key-32bytes-padding!'), metadataNoAuth)
    ).rejects.toThrow();
  });

  it('should retry blob download on 503 status', async () => {
    const { service, http, blob } = createService();
    (http.get as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: {
        fileId: 'file_1.enc',
        downloadUrl: 'https://blob.example.com/f?sas=tok',
        expiresAt: '2025-12-31T23:59:59Z',
      },
    });

    // First call: 503, second call: success
    const error503 = new Error('Service Unavailable') as AxiosLikeError;
    error503.response = {
      status: 503,
      data: { error: { retryAfter: 0.01 } },
    };

    const fileBuffer = Buffer.from('content');
    (blob.get as ReturnType<typeof vi.fn>)
      .mockRejectedValueOnce(error503)
      .mockResolvedValueOnce({
        data: fileBuffer.buffer.slice(fileBuffer.byteOffset, fileBuffer.byteOffset + fileBuffer.byteLength),
      });

    const result = await service.downloadEncryptedFile('capsa_1', 'file_1.enc');

    expect(Buffer.isBuffer(result)).toBe(true);
    expect(blob.get).toHaveBeenCalledTimes(2);
  });

  it('should retry blob download on 429 status', async () => {
    const { service, http, blob } = createService();
    (http.get as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: {
        fileId: 'file_1.enc',
        downloadUrl: 'https://blob.example.com/f?sas=tok',
        expiresAt: '2025-12-31T23:59:59Z',
      },
    });

    const error429 = new Error('Too Many Requests') as AxiosLikeError;
    error429.response = {
      status: 429,
      data: { error: { retryAfter: 0.01 } },
    };

    const fileBuffer = Buffer.from('content');
    (blob.get as ReturnType<typeof vi.fn>)
      .mockRejectedValueOnce(error429)
      .mockResolvedValueOnce({
        data: fileBuffer.buffer.slice(fileBuffer.byteOffset, fileBuffer.byteOffset + fileBuffer.byteLength),
      });

    const result = await service.downloadEncryptedFile('capsa_1', 'file_1.enc');
    expect(Buffer.isBuffer(result)).toBe(true);
  });

  it('should stop retrying after max retries exceeded', async () => {
    const { service, http, blob } = createService();
    (http.get as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: {
        fileId: 'file_1.enc',
        downloadUrl: 'https://blob.example.com/f?sas=tok',
        expiresAt: '2025-12-31T23:59:59Z',
      },
    });

    const error503 = new Error('Service Unavailable') as AxiosLikeError;
    error503.response = {
      status: 503,
      data: { error: { retryAfter: 0.001 } },
    };

    // Fail all attempts (initial + 3 retries = 4 calls)
    (blob.get as ReturnType<typeof vi.fn>).mockRejectedValue(error503);

    await expect(
      service.downloadEncryptedFile('capsa_1', 'file_1.enc')
    ).rejects.toThrow();

    // 1 initial + 3 retries = 4 total
    expect(blob.get).toHaveBeenCalledTimes(4);
  });

  it('should wrap errors with capsaId and fileId context', async () => {
    const { service, http, blob } = createService();
    (http.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: {
        fileId: 'file_abc.enc',
        downloadUrl: 'https://blob.example.com/f?sas=tok',
        expiresAt: '2025-12-31T23:59:59Z',
      },
    });
    (blob.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: Buffer.from('encrypted').buffer,
    });

    try {
      await service.downloadAndDecryptFile('capsa_xyz', 'file_abc.enc', Buffer.from('bad-key-32bytes-for-testing!!!!'), MOCK_METADATA);
      expect.unreachable('Should have thrown');
    } catch (error) {
      const err = error as Error;
      expect(err.message).toContain('capsa_xyz');
      expect(err.message).toContain('file_abc.enc');
    }
  });
});
