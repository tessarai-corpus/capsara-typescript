/**
 * Tests for upload-service.ts - Capsa upload service
 * @file tests/unit/internal/services/upload-service.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import type { ClientRequest } from 'http';

// Mock http and https modules using hoisted variable
const { mockRequestFn } = vi.hoisted(() => {
  return {
    mockRequestFn: vi.fn(),
  };
});

vi.mock('http', async (importOriginal) => {
  const actual = await importOriginal<typeof import('http')>();
  return {
    ...actual,
    request: mockRequestFn,
    Agent: vi.fn().mockImplementation(function () {
      return {
        maxSockets: 10,
        keepAlive: true,
        destroy: vi.fn(),
      };
    }),
  };
});

vi.mock('https', async (importOriginal) => {
  const actual = await importOriginal<typeof import('https')>();
  return {
    ...actual,
    request: mockRequestFn,
    Agent: vi.fn().mockImplementation(function () {
      return {
        maxSockets: 10,
        keepAlive: true,
        destroy: vi.fn(),
      };
    }),
  };
});

// Mock the multipart builder
vi.mock('../../../../src/internal/upload/multipart-builder.js', () => ({
  CapsasMultipartBuilder: vi.fn().mockImplementation(function () {
    return {
      addMetadata: vi.fn().mockReturnThis(),
      addCapsaMetadata: vi.fn().mockReturnThis(),
      addFileBinary: vi.fn().mockReturnThis(),
      build: vi.fn().mockReturnValue(Buffer.from('mock-multipart-body')),
      getContentType: vi.fn().mockReturnValue('multipart/form-data; boundary=----MockBoundary'),
    };
  }),
}));

// Mock the http-client
vi.mock('../../../../src/internal/config/http-client.js', () => ({
  createAgentForProtocol: vi.fn(() => ({
    maxSockets: 10,
    keepAlive: true,
  })),
}));

import {
  UploadService,
  type UploadServiceOptions,
  type SendResult,
} from '../../../../src/internal/services/upload-service.js';
import type { CapsaBuilder } from '../../../../src/builder/capsa-builder.js';
import { CapsaraError } from '../../../../src/errors/capsara-error.js';
import type { KeyManager } from '../../../../src/internal/services/key-service.js';
import type { TokenRefresher } from '../../../../src/internal/config/token-refresh.js';

// Helper to create mock CapsaBuilder
function createMockBuilder(fileCount: number = 1): CapsaBuilder {
  return {
    getFileCount: vi.fn().mockReturnValue(fileCount),
    getRecipientIds: vi.fn().mockReturnValue(['recipient_1']),
    build: vi.fn().mockResolvedValue({
      capsa: { id: 'capsa_123' },
      files: Array(fileCount)
        .fill(null)
        .map((_, i) => ({
          data: Buffer.from(`file-${i}`),
          metadata: { fileId: `file_${i}.enc` },
        })),
    }),
  } as unknown as CapsaBuilder;
}

// Helper to create mock KeyManager
function createMockKeyManager(): KeyManager {
  return {
    fetchPartyKeys: vi.fn().mockResolvedValue({
      party_creator: { id: 'party_creator', publicKey: 'public-key' },
      recipient_1: { id: 'recipient_1', publicKey: 'public-key' },
    }),
  } as unknown as KeyManager;
}

// Helper to create default options
function createDefaultOptions(overrides?: Partial<UploadServiceOptions>): UploadServiceOptions {
  return {
    baseUrl: 'https://api.example.com',
    keyManager: createMockKeyManager(),
    getToken: () => 'test-token',
    timeoutConfig: {
      apiTimeout: 60000,
      uploadTimeout: 120000,
      downloadTimeout: 30000,
      connectTimeout: 30000,
      keepAliveInterval: 30000,
      maxSockets: 50,
      maxFreeSockets: 10,
    },
    retryConfig: {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 30000,
      enableLogging: false,
      logger: { log: vi.fn() },
    },
    logger: { log: vi.fn() },
    maxBatchSize: 100,
    getLimits: async () => ({
      maxFileSize: 50 * 1024 * 1024,
      maxFilesPerCapsa: 500,
      maxTotalSize: 500 * 1024 * 1024,
      maxRequestSize: 2 * 1024 * 1024 * 1024,
    }),
    ...overrides,
  };
}

// Helper to setup mock HTTP request/response
interface MockResponseConfig {
  statusCode: number;
  data: unknown;
}

function setupMockRequest(configs: MockResponseConfig | MockResponseConfig[]): void {
  const configsArray = Array.isArray(configs) ? [...configs] : [configs];
  let callIndex = 0;

  mockRequestFn.mockImplementation((_options, callback) => {
    const config = configsArray[Math.min(callIndex, configsArray.length - 1)]!;
    callIndex++;

    const mockResponse = {
      statusCode: config.statusCode,
      on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
        if (event === 'data') {
          const responseData =
            typeof config.data === 'string' ? config.data : JSON.stringify(config.data);
          setImmediate(() => handler(Buffer.from(responseData)));
        }
        if (event === 'end') {
          setImmediate(() => handler());
        }
        return mockResponse;
      }),
    };

    const mockReq = {
      on: vi.fn().mockReturnThis(),
      write: vi.fn(),
      end: vi.fn(),
      destroy: vi.fn(),
    };

    if (callback) {
      setImmediate(() => callback(mockResponse));
    }

    return mockReq as unknown as ClientRequest;
  });
}

function setupMockRequestWithError(errorMessage: string): void {
  mockRequestFn.mockImplementation(() => {
    const mockReq = {
      on: vi.fn((event: string, handler: (err?: Error) => void) => {
        if (event === 'error') {
          setImmediate(() => handler(new Error(errorMessage)));
        }
        return mockReq;
      }),
      write: vi.fn(),
      end: vi.fn(),
      destroy: vi.fn(),
    };

    return mockReq as unknown as ClientRequest;
  });
}

function setupMockRequestWithTimeout(): void {
  mockRequestFn.mockImplementation(() => {
    const mockReq = {
      on: vi.fn((event: string, handler: () => void) => {
        if (event === 'timeout') {
          setImmediate(() => handler());
        }
        return mockReq;
      }),
      write: vi.fn(),
      end: vi.fn(),
      destroy: vi.fn(),
    };

    return mockReq as unknown as ClientRequest;
  });
}

describe('UploadService', () => {
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
      const service = new UploadService(options);

      expect(service).toBeInstanceOf(UploadService);
    });
  });

  describe('sendCapsas', () => {
    describe('validation', () => {
      it('should throw when no capsas provided', async () => {
        const service = new UploadService(createDefaultOptions());

        await expect(service.sendCapsas([], 'creator_123')).rejects.toThrow('No capsas provided');
      });

      it('reports every pre-send check as VALIDATION_ERROR with status 0', async () => {
        const service = new UploadService(createDefaultOptions());
        const noRecipient = createMockBuilder();
        (noRecipient.getRecipientIds as Mock).mockReturnValue([]);

        await expect(service.sendCapsas([], 'creator_123')).rejects.toMatchObject({
          name: 'CapsaraError', code: 'VALIDATION_ERROR', statusCode: 0,
        });
        await expect(service.sendCapsas(Array.from({ length: 501 }, () => createMockBuilder()), 'creator_123'))
          .rejects.toMatchObject({ code: 'VALIDATION_ERROR', statusCode: 0 });
        await expect(service.sendCapsas([createMockBuilder(), noRecipient], 'creator_123'))
          .rejects.toMatchObject({ code: 'VALIDATION_ERROR', statusCode: 0, details: { index: 1 } });
        await expect(service.sendCapsas([createMockBuilder(501)], 'creator_123'))
          .rejects.toMatchObject({ code: 'VALIDATION_ERROR', statusCode: 0, details: { index: 0 } });
        expect(mockRequestFn).not.toHaveBeenCalled();
      });

      it('accepts exactly 500 capsas and 500 files per capsa', async () => {
        setupMockRequest({ statusCode: 201, data: { created: [] } });
        const service = new UploadService(createDefaultOptions({ maxBatchSize: 500 }));

        const pending = service.sendCapsas([createMockBuilder(500)], 'creator_123');
        await vi.runAllTimersAsync();

        await expect(pending).resolves.toBeDefined();
      });

      it('should throw when more than 500 capsas provided', async () => {
        const service = new UploadService(createDefaultOptions());
        const builders = Array(501)
          .fill(null)
          .map(() => createMockBuilder());

        await expect(service.sendCapsas(builders, 'creator_123')).rejects.toThrow(
          'limited to 500 capsas'
        );
      });

      it('should throw when a capsa exceeds file limit', async () => {
        const service = new UploadService(createDefaultOptions());
        const builders = [createMockBuilder(501)]; // 501 files in one capsa

        await expect(service.sendCapsas(builders, 'creator_123')).rejects.toThrow(
          'exceeding the batch limit'
        );
      });

      it('should throw before any network call when a capsa has no recipient', async () => {
        const options = createDefaultOptions();
        const service = new UploadService(options);
        const noRecipient = createMockBuilder();
        (noRecipient.getRecipientIds as ReturnType<typeof vi.fn>).mockReturnValue([]);

        await expect(service.sendCapsas([createMockBuilder(), noRecipient], 'creator_123')).rejects.toThrow(
          'Capsa at index 1 has no recipient. Call addRecipient() with the party this capsa is sent to.'
        );
        expect(options.keyManager.fetchPartyKeys).not.toHaveBeenCalled();
      });
    });

    describe('successful upload', () => {
      it('should send single capsa successfully', async () => {
        const mockResult = {
          batchId: 'batch_123',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_123', index: 0 }],
        };
        setupMockRequest({ statusCode: 200, data: mockResult });

        const service = new UploadService(createDefaultOptions());
        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.successful).toBe(1);
        expect(result.failed).toBe(0);
        expect(result.created).toHaveLength(1);
      });

      it('should send multiple capsas successfully', async () => {
        const mockResult = {
          batchId: 'batch_123',
          successful: 3,
          failed: 0,
          created: [
            { packageId: 'pkg_1', index: 0 },
            { packageId: 'pkg_2', index: 1 },
            { packageId: 'pkg_3', index: 2 },
          ],
        };
        setupMockRequest({ statusCode: 200, data: mockResult });

        const service = new UploadService(createDefaultOptions());
        const builders = [createMockBuilder(), createMockBuilder(), createMockBuilder()];
        const resultPromise = service.sendCapsas(builders, 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.successful).toBe(3);
        expect(result.created).toHaveLength(3);
      });

      it('should send one capsa per principal in a single batch', async () => {
        setupMockRequest({
          statusCode: 200,
          data: {
            batchId: 'batch_123',
            successful: 2,
            failed: 0,
            created: [
              { packageId: 'pkg_agent', index: 0 },
              { packageId: 'pkg_vendor', index: 1 },
            ],
          },
        });

        const options = createDefaultOptions();
        const service = new UploadService(options);
        const toAgent = createMockBuilder();
        (toAgent.getRecipientIds as ReturnType<typeof vi.fn>).mockReturnValue(['agent_1']);
        const toVendor = createMockBuilder();
        (toVendor.getRecipientIds as ReturnType<typeof vi.fn>).mockReturnValue(['vendor_1']);

        const resultPromise = service.sendCapsas([toAgent, toVendor], 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.successful).toBe(2);
        // Keys for both principals are fetched together, and each builder gets the full set
        expect(options.keyManager.fetchPartyKeys).toHaveBeenCalledTimes(1);
        expect(options.keyManager.fetchPartyKeys).toHaveBeenCalledWith(['creator_123', 'agent_1', 'vendor_1']);
        expect(toAgent.build).toHaveBeenCalledTimes(1);
        expect(toVendor.build).toHaveBeenCalledTimes(1);
      });

      it('should handle 207 multi-status response', async () => {
        const mockResult = {
          batchId: 'batch_123',
          successful: 2,
          failed: 1,
          partialSuccess: true,
          created: [
            { packageId: 'pkg_1', index: 0 },
            { packageId: 'pkg_2', index: 1 },
          ],
          errors: [{ index: 2, packageId: 'pkg_3', error: 'Validation failed' }],
        };
        setupMockRequest({ statusCode: 207, data: mockResult });

        const service = new UploadService(createDefaultOptions());
        const builders = [createMockBuilder(), createMockBuilder(), createMockBuilder()];
        const resultPromise = service.sendCapsas(builders, 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.successful).toBe(2);
        expect(result.failed).toBe(1);
        expect(result.partialSuccess).toBe(true);
      });
    });

    describe('batching', () => {
      it('should split capsas into batches based on maxBatchSize', async () => {
        const batch1Result = {
          batchId: 'batch_1',
          successful: 50,
          failed: 0,
          created: Array(50)
            .fill(null)
            .map((_, i) => ({ packageId: `pkg_${i}`, index: i })),
        };
        const batch2Result = {
          batchId: 'batch_2',
          successful: 50,
          failed: 0,
          created: Array(50)
            .fill(null)
            .map((_, i) => ({ packageId: `pkg_${50 + i}`, index: i })),
        };
        setupMockRequest([
          { statusCode: 200, data: batch1Result },
          { statusCode: 200, data: batch2Result },
        ]);

        const options = createDefaultOptions({ maxBatchSize: 50 });
        const service = new UploadService(options);

        // 100 capsas should be split into 2 batches of 50
        const builders = Array(100)
          .fill(null)
          .map(() => createMockBuilder());
        const resultPromise = service.sendCapsas(builders, 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.successful).toBe(100); // 50 + 50
      });

      it('should split capsas into batches based on file count limit', async () => {
        const batch1Result = {
          batchId: 'batch_1',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };
        const batch2Result = {
          batchId: 'batch_2',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_2', index: 0 }],
        };
        setupMockRequest([
          { statusCode: 200, data: batch1Result },
          { statusCode: 200, data: batch2Result },
        ]);

        const options = createDefaultOptions({ maxBatchSize: 100 });
        const service = new UploadService(options);

        // 2 capsas with 300 files each should be in separate batches (500 file limit)
        const builders = [createMockBuilder(300), createMockBuilder(300)];
        const resultPromise = service.sendCapsas(builders, 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.successful).toBe(2); // 1 + 1
      });

      describe('maxFilesPerRequest', () => {
        function optionsWithFileLimit(maxFilesPerRequest?: number): UploadServiceOptions {
          return createDefaultOptions({
            maxBatchSize: 100,
            getLimits: async () => ({
              maxFileSize: 50 * 1024 * 1024,
              maxFilesPerCapsa: 10_000,
              maxTotalSize: 500 * 1024 * 1024,
              maxRequestSize: 2 * 1024 * 1024 * 1024,
              ...(maxFilesPerRequest !== undefined && { maxFilesPerRequest }),
            }),
          });
        }

        async function requestCount(builders: CapsaBuilder[], maxFilesPerRequest?: number): Promise<number> {
          setupMockRequest({ statusCode: 200, data: { created: [] } });
          const service = new UploadService(optionsWithFileLimit(maxFilesPerRequest));
          const pending = service.sendCapsas(builders, 'creator_123');
          await vi.runAllTimersAsync();
          await pending;
          return mockRequestFn.mock.calls.length;
        }

        it('accepts a capsa above 500 files when the server publishes a higher limit', async () => {
          await expect(requestCount([createMockBuilder(501)], 5000)).resolves.toBe(1);
        });

        it('keeps capsas together up to the published limit', async () => {
          await expect(requestCount([createMockBuilder(300), createMockBuilder(300)], 5000)).resolves.toBe(1);
        });

        it('splits a batch on file count at the published limit', async () => {
          await expect(requestCount([createMockBuilder(5), createMockBuilder(5)], 10)).resolves.toBe(1);
          mockRequestFn.mockClear();
          await expect(requestCount([createMockBuilder(5), createMockBuilder(6)], 10)).resolves.toBe(2);
        });

        it('rejects a capsa above the published limit', async () => {
          const service = new UploadService(optionsWithFileLimit(10));

          await expect(service.sendCapsas([createMockBuilder(11)], 'creator_123')).rejects.toMatchObject({
            code: 'VALIDATION_ERROR',
            message: 'Capsa at index 0 has 11 files, exceeding the batch limit of 10 files.',
          });
          expect(mockRequestFn).not.toHaveBeenCalled();
        });

        it.each([
          ['absent', undefined],
          ['zero', 0],
          ['negative', -1],
        ])('falls back to 500 files when maxFilesPerRequest is %s', async (_label, value) => {
          await expect(requestCount([createMockBuilder(300), createMockBuilder(300)], value)).resolves.toBe(2);
          mockRequestFn.mockClear();
          const service = new UploadService(optionsWithFileLimit(value));
          await expect(service.sendCapsas([createMockBuilder(501)], 'creator_123'))
            .rejects.toThrow('exceeding the batch limit of 500 files');
        });

        it('fetches the limits once per send', async () => {
          setupMockRequest({ statusCode: 200, data: { created: [] } });
          const getLimits = vi.fn(async () => ({
            maxFileSize: 50 * 1024 * 1024,
            maxFilesPerCapsa: 500,
            maxTotalSize: 500 * 1024 * 1024,
            maxFilesPerRequest: 10,
          }));
          const service = new UploadService(createDefaultOptions({ getLimits }));
          const pending = service.sendCapsas([createMockBuilder(6), createMockBuilder(6), createMockBuilder(6)], 'creator_123');
          await vi.runAllTimersAsync();
          await pending;

          expect(mockRequestFn).toHaveBeenCalledTimes(3);
          expect(getLimits).toHaveBeenCalledTimes(1);
        });
      });

      it('should log batch information when logging enabled', async () => {
        const mockResult = {
          batchId: 'batch_123',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };
        setupMockRequest({ statusCode: 200, data: mockResult });

        const logger = { log: vi.fn() };
        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 3,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: true,
            logger: { log: vi.fn() },
          },
          logger,
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();
        await resultPromise;

        expect(logger.log).toHaveBeenCalled();
      });
    });

    describe('error handling', () => {
      it('should handle batch failure and continue with next batch', async () => {
        const batch2Result = {
          batchId: 'batch_2',
          successful: 50,
          failed: 0,
          created: Array(50)
            .fill(null)
            .map((_, i) => ({ packageId: `pkg_${i}`, index: i })),
        };
        setupMockRequest([
          { statusCode: 500, data: { error: 'Server error' } },
          { statusCode: 200, data: batch2Result },
        ]);

        const options = createDefaultOptions({
          maxBatchSize: 50,
          retryConfig: {
            maxRetries: 0, // No retries for this test
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: false,
            logger: { log: vi.fn() },
          },
        });
        const service = new UploadService(options);

        const builders = Array(100)
          .fill(null)
          .map(() => createMockBuilder());
        const resultPromise = service.sendCapsas(builders, 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.successful).toBe(50);
        expect(result.failed).toBe(50);
        expect(result.errors).toHaveLength(50);
      });

      it('should log batch failure when logging enabled', async () => {
        const batch2Result = {
          batchId: 'batch_2',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };
        setupMockRequest([
          { statusCode: 500, data: { error: 'Server error' } },
          { statusCode: 200, data: batch2Result },
        ]);

        const logger = { log: vi.fn() };
        const options = createDefaultOptions({
          maxBatchSize: 1,
          retryConfig: {
            maxRetries: 0,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: true,
            logger: { log: vi.fn() },
          },
          logger,
        });
        const service = new UploadService(options);

        const builders = [createMockBuilder(), createMockBuilder()];
        const resultPromise = service.sendCapsas(builders, 'creator_123');
        await vi.runAllTimersAsync();
        await resultPromise;

        const logCalls = (logger.log as Mock).mock.calls.map((call) => call[0] as string);
        expect(logCalls.some((msg) => msg.includes('failed'))).toBe(true);
      });

      it('should handle parse error', async () => {
        setupMockRequest({ statusCode: 200, data: 'invalid-json' });

        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 0,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: false,
            logger: { log: vi.fn() },
          },
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        // Parse errors are caught at the batch level
        expect(result.failed).toBe(1);
        expect(result.errors?.[0]?.error).toContain('Failed to parse');
      });

      it('should handle non-retryable error status', async () => {
        setupMockRequest({ statusCode: 400, data: { error: 'Bad request' } });

        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 3,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: false,
            logger: { log: vi.fn() },
          },
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.failed).toBe(1);
        // Not in the standard error shape: HTTP_<status> and the reason phrase
        expect(result.errors?.[0]?.code).toBe('HTTP_400');
        expect(result.errors?.[0]?.error).toBe('Bad Request');
        // Should not retry for 400
        expect(mockRequestFn).toHaveBeenCalledTimes(1);
      });

      it('should keep each capsa\'s code when the server rejects every capsa', async () => {
        setupMockRequest({
          statusCode: 422,
          data: {
            success: false,
            successful: 0,
            failed: 2,
            created: [],
            errors: [
              { index: 0, packageId: 'pkg_0', code: 'KEYCHAIN_SINGLE_PRINCIPAL_REQUIRED', message: 'Exactly one principal is required' },
              { index: 1, packageId: 'pkg_1', code: 'DELEGATE_PRINCIPAL_MISMATCH', message: 'Delegate acts for another party' },
            ],
          },
        });

        const service = new UploadService(createDefaultOptions());
        const resultPromise = service.sendCapsas([createMockBuilder(), createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.failed).toBe(2);
        expect(result.errors).toEqual([
          { index: 0, packageId: 'pkg_0', error: 'Exactly one principal is required', code: 'KEYCHAIN_SINGLE_PRINCIPAL_REQUIRED' },
          { index: 1, packageId: 'pkg_1', error: 'Delegate acts for another party', code: 'DELEGATE_PRINCIPAL_MISMATCH' },
        ]);
      });

      it('should carry the server code on a rejected request without per-capsa failures', async () => {
        setupMockRequest({
          statusCode: 400,
          data: { error: { code: 'DELEGATE_PRINCIPAL_MISMATCH', message: 'Delegate acts for another party' } },
        });

        const service = new UploadService(createDefaultOptions());
        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.errors?.[0]).toMatchObject({ code: 'DELEGATE_PRINCIPAL_MISMATCH', error: 'Delegate acts for another party' });
      });

      it('should pass through per-capsa codes in a 207 response', async () => {
        setupMockRequest({
          statusCode: 207,
          data: {
            batchId: 'batch_123',
            successful: 1,
            failed: 1,
            partialSuccess: true,
            created: [{ packageId: 'pkg_1', index: 0 }],
            errors: [{ index: 1, packageId: 'pkg_2', error: 'Delegate acts for another party', code: 'DELEGATE_PRINCIPAL_MISMATCH' }],
          },
        });

        const service = new UploadService(createDefaultOptions());
        const resultPromise = service.sendCapsas([createMockBuilder(), createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.errors?.[0]?.code).toBe('DELEGATE_PRINCIPAL_MISMATCH');
      });

      it('should handle request timeout', async () => {
        setupMockRequestWithTimeout();

        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 0,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: false,
            logger: { log: vi.fn() },
          },
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.failed).toBe(1);
        expect(result.errors?.[0]?.error).toContain('timeout');
      });

      it('should handle request error', async () => {
        setupMockRequestWithError('Connection refused');

        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 0,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: false,
            logger: { log: vi.fn() },
          },
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.failed).toBe(1);
        expect(result.errors?.[0]?.error).toContain('Connection refused');
      });
    });

    describe('request size splitting', () => {
      /** Builder whose built capsa carries a known number of encrypted bytes. */
      function createSizedBuilder(bytes: number): CapsaBuilder {
        return {
          getFileCount: vi.fn().mockReturnValue(1),
          getRecipientIds: vi.fn().mockReturnValue(['recipient_1']),
          build: vi.fn().mockResolvedValue({
            capsa: { id: 'capsa_123' },
            files: [{
              data: Buffer.alloc(bytes),
              metadata: { fileId: 'file_0.enc' },
            }],
          }),
        } as unknown as CapsaBuilder;
      }

      const successResult = {
        batchId: 'batch_123',
        successful: 1,
        failed: 0,
        created: [{ packageId: 'pkg_1', index: 0 }],
      };

      it('splits one batch into several requests when encrypted bytes exceed the limit', async () => {
        setupMockRequest({ statusCode: 200, data: successResult });

        const options = createDefaultOptions({
          getLimits: async () => ({
            maxFileSize: 50 * 1024 * 1024,
            maxFilesPerCapsa: 500,
            maxTotalSize: 500 * 1024 * 1024,
            maxRequestSize: 1000,
          }),
        });
        const service = new UploadService(options);

        // Three capsas of 400 bytes against a 1000 byte request limit → 2 requests
        const resultPromise = service.sendCapsas(
          [createSizedBuilder(400), createSizedBuilder(400), createSizedBuilder(400)],
          'creator_123'
        );

        await vi.runAllTimersAsync();
        await resultPromise;

        expect(mockRequestFn.mock.calls.length).toBe(2);
      });

      it('sends a single request when the batch fits', async () => {
        setupMockRequest({ statusCode: 200, data: successResult });

        const options = createDefaultOptions({
          getLimits: async () => ({
            maxFileSize: 50 * 1024 * 1024,
            maxFilesPerCapsa: 500,
            maxTotalSize: 500 * 1024 * 1024,
            maxRequestSize: 1000,
          }),
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas(
          [createSizedBuilder(100), createSizedBuilder(100)],
          'creator_123'
        );

        await vi.runAllTimersAsync();
        await resultPromise;

        expect(mockRequestFn.mock.calls.length).toBe(1);
      });

      describe('JSON field bytes', () => {
        /** Builder whose capsa JSON serializes to exactly jsonBytes UTF-8 bytes. */
        function createJsonBuilder(fileBytes: number, jsonBytes: number): CapsaBuilder {
          const overhead = Buffer.byteLength(JSON.stringify({ id: 'capsa_123', pad: '' }), 'utf-8');
          const capsa = { id: 'capsa_123', pad: 'x'.repeat(jsonBytes - overhead) };
          expect(Buffer.byteLength(JSON.stringify(capsa), 'utf-8')).toBe(jsonBytes);
          return {
            getFileCount: vi.fn().mockReturnValue(1),
            getRecipientIds: vi.fn().mockReturnValue(['recipient_1']),
            build: vi.fn().mockResolvedValue({
              capsa,
              files: [{ data: Buffer.alloc(fileBytes), metadata: { fileId: 'file_0.enc' } }],
            }),
          } as unknown as CapsaBuilder;
        }

        async function requestCount(builders: CapsaBuilder[], limits: { maxRequestSize?: number; maxRequestFieldBytes?: number }): Promise<number> {
          setupMockRequest({ statusCode: 200, data: successResult });
          const service = new UploadService(createDefaultOptions({
            getLimits: async () => ({ maxFileSize: 50 * 1024 * 1024, maxFilesPerCapsa: 500, maxTotalSize: 500 * 1024 * 1024, ...limits }),
          }));
          const pending = service.sendCapsas(builders, 'creator_123');
          await vi.runAllTimersAsync();
          await pending;
          return mockRequestFn.mock.calls.length;
        }

        it('counts each capsa JSON part together with its file bytes against maxRequestSize', async () => {
          await expect(requestCount([createJsonBuilder(400, 100), createJsonBuilder(400, 100)], { maxRequestSize: 1000 })).resolves.toBe(1);
          mockRequestFn.mockClear();
          await expect(requestCount([createJsonBuilder(400, 100), createJsonBuilder(400, 101)], { maxRequestSize: 1000 })).resolves.toBe(2);
        });

        it('keeps the sum of JSON parts per request within maxRequestFieldBytes', async () => {
          const builders = [createJsonBuilder(1, 400), createJsonBuilder(1, 400), createJsonBuilder(1, 400)];

          await expect(requestCount(builders, { maxRequestSize: 1_000_000, maxRequestFieldBytes: 1000 })).resolves.toBe(2);
        });

        it('allows JSON parts that add up to exactly maxRequestFieldBytes in one request', async () => {
          await expect(requestCount([createJsonBuilder(1, 500), createJsonBuilder(1, 500)], { maxRequestSize: 1_000_000, maxRequestFieldBytes: 1000 }))
            .resolves.toBe(1);
        });

        it('gives a capsa whose JSON alone exceeds maxRequestFieldBytes its own request', async () => {
          const builders = [createJsonBuilder(1, 100), createJsonBuilder(1, 1500), createJsonBuilder(1, 100)];

          await expect(requestCount(builders, { maxRequestSize: 1_000_000, maxRequestFieldBytes: 1000 })).resolves.toBe(3);
        });

        it.each([
          ['missing', undefined],
          ['zero', 0],
          ['negative', -1],
        ])('falls back to 64 MiB when maxRequestFieldBytes is %s', async (_label, value) => {
          const builders = [createJsonBuilder(1, 400), createJsonBuilder(1, 400), createJsonBuilder(1, 400)];
          const limits = value === undefined ? { maxRequestSize: 1_000_000 } : { maxRequestSize: 1_000_000, maxRequestFieldBytes: value };

          await expect(requestCount(builders, limits)).resolves.toBe(1);
        });

        it('measures JSON in UTF-8 bytes, not characters', async () => {
          const multibyte = (jsonBytes: number): CapsaBuilder => {
            const base = Buffer.byteLength(JSON.stringify({ id: 'capsa_123', pad: '' }), 'utf-8');
            const capsa = { id: 'capsa_123', pad: 'é'.repeat((jsonBytes - base) / 2) };
            return {
              getFileCount: vi.fn().mockReturnValue(1),
              getRecipientIds: vi.fn().mockReturnValue(['recipient_1']),
              build: vi.fn().mockResolvedValue({ capsa, files: [{ data: Buffer.alloc(1), metadata: { fileId: 'f.enc' } }] }),
            } as unknown as CapsaBuilder;
          };

          await expect(requestCount([multibyte(600), multibyte(600)], { maxRequestSize: 1_000_000, maxRequestFieldBytes: 1000 })).resolves.toBe(2);
        });
      });

      it('gives an oversized capsa its own request rather than failing its neighbours', async () => {
        setupMockRequest({ statusCode: 200, data: successResult });

        const options = createDefaultOptions({
          getLimits: async () => ({
            maxFileSize: 50 * 1024 * 1024,
            maxFilesPerCapsa: 500,
            maxTotalSize: 500 * 1024 * 1024,
            maxRequestSize: 1000,
          }),
        });
        const service = new UploadService(options);

        // The 5000-byte capsa cannot be split further; it should not drag the small
        // ones into a request the server would refuse
        const resultPromise = service.sendCapsas(
          [createSizedBuilder(100), createSizedBuilder(5000), createSizedBuilder(100)],
          'creator_123'
        );

        await vi.runAllTimersAsync();
        await resultPromise;

        expect(mockRequestFn.mock.calls.length).toBe(3);
      });

      it('falls back to a default limit when the API advertises none', async () => {
        setupMockRequest({ statusCode: 200, data: successResult });

        const options = createDefaultOptions({
          getLimits: async () => ({
            maxFileSize: 50 * 1024 * 1024,
            maxFilesPerCapsa: 500,
            maxTotalSize: 500 * 1024 * 1024,
          }),
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas([createSizedBuilder(400)], 'creator_123');

        await vi.runAllTimersAsync();
        await resultPromise;

        expect(mockRequestFn.mock.calls.length).toBe(1);
      });
    });

    describe('delegate set mismatch', () => {
      const successResult = {
        batchId: 'batch_123',
        successful: 1,
        failed: 0,
        created: [{ packageId: 'pkg_1', index: 0 }],
      };

      const mismatchResponse = {
        statusCode: 409,
        data: {
          error: {
            code: 'KEYCHAIN_DELEGATES_MISMATCH',
            message: 'Keychain does not match the current delegate registrations.',
            details: { problems: ['recipient "recipient_1" has registered delegate "ams_1"'] },
          },
        },
      };

      it('should re-fetch party keys and rebuild on a delegate set mismatch', async () => {
        setupMockRequest([mismatchResponse, { statusCode: 200, data: successResult }]);

        const options = createDefaultOptions();
        const builder = createMockBuilder();
        const service = new UploadService(options);
        const resultPromise = service.sendCapsas([builder], 'creator_123');

        await vi.runAllTimersAsync();

        const result = await resultPromise;
        expect(result.successful).toBe(1);
        expect(options.keyManager.fetchPartyKeys).toHaveBeenCalledTimes(2);
        expect(builder.build).toHaveBeenCalledTimes(2);
      });

      it('should give up after one rebuild and surface the error', async () => {
        setupMockRequest([mismatchResponse, mismatchResponse]);

        const options = createDefaultOptions();
        const service = new UploadService(options);
        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');

        await vi.runAllTimersAsync();

        const result = await resultPromise;
        expect(result.failed).toBe(1);
        expect(result.errors?.[0]?.error).toContain('delegate registrations');
        expect(options.keyManager.fetchPartyKeys).toHaveBeenCalledTimes(2);
      });

      it('should not rebuild for errors other than a delegate set mismatch', async () => {
        setupMockRequest({
          statusCode: 400,
          data: { error: { code: 'INVALID_KEYCHAIN', message: 'no such party' } },
        });

        const options = createDefaultOptions();
        const service = new UploadService(options);
        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');

        await vi.runAllTimersAsync();

        const result = await resultPromise;
        expect(result.failed).toBe(1);
        expect(result.errors?.[0]?.error).toContain('no such party');
        expect(options.keyManager.fetchPartyKeys).toHaveBeenCalledTimes(1);
      });
    });

    describe('retry logic', () => {
      it('should retry on 503 status', async () => {
        let callCount = 0;

        const successResult = {
          batchId: 'batch_123',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };

        mockRequestFn.mockImplementation((_options, callback) => {
          callCount++;
          const statusCode = callCount < 2 ? 503 : 200;
          const data =
            callCount < 2 ? { error: { retryAfter: 1 } } : successResult;

          const mockResponse = {
            statusCode,
            on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
              if (event === 'data') {
                setImmediate(() => handler(Buffer.from(JSON.stringify(data))));
              }
              if (event === 'end') {
                setImmediate(() => handler());
              }
              return mockResponse;
            }),
          };

          const mockReq = {
            on: vi.fn().mockReturnThis(),
            write: vi.fn(),
            end: vi.fn(),
            destroy: vi.fn(),
          };

          if (callback) {
            setImmediate(() => callback(mockResponse));
          }

          return mockReq as unknown as ClientRequest;
        });

        const service = new UploadService(createDefaultOptions());
        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');

        await vi.runAllTimersAsync();

        const result = await resultPromise;
        expect(result.successful).toBe(1);
        expect(callCount).toBe(2);
      });

      it('should retry on 429 status', async () => {
        let callCount = 0;

        const successResult = {
          batchId: 'batch_123',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };

        mockRequestFn.mockImplementation((_options, callback) => {
          callCount++;
          const statusCode = callCount < 2 ? 429 : 200;
          const data = callCount < 2 ? { error: {} } : successResult;

          const mockResponse = {
            statusCode,
            on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
              if (event === 'data') {
                setImmediate(() => handler(Buffer.from(JSON.stringify(data))));
              }
              if (event === 'end') {
                setImmediate(() => handler());
              }
              return mockResponse;
            }),
          };

          const mockReq = {
            on: vi.fn().mockReturnThis(),
            write: vi.fn(),
            end: vi.fn(),
            destroy: vi.fn(),
          };

          if (callback) {
            setImmediate(() => callback(mockResponse));
          }

          return mockReq as unknown as ClientRequest;
        });

        const service = new UploadService(createDefaultOptions());
        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');

        await vi.runAllTimersAsync();

        const result = await resultPromise;
        expect(result.successful).toBe(1);
      });

      it('should stop retrying after max retries exceeded', async () => {
        let callCount = 0;

        mockRequestFn.mockImplementation((_options, callback) => {
          callCount++;

          const mockResponse = {
            statusCode: 503,
            on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
              if (event === 'data') {
                setImmediate(() => handler(Buffer.from(JSON.stringify({ error: {} }))));
              }
              if (event === 'end') {
                setImmediate(() => handler());
              }
              return mockResponse;
            }),
          };

          const mockReq = {
            on: vi.fn().mockReturnThis(),
            write: vi.fn(),
            end: vi.fn(),
            destroy: vi.fn(),
          };

          if (callback) {
            setImmediate(() => callback(mockResponse));
          }

          return mockReq as unknown as ClientRequest;
        });

        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 2,
            baseDelay: 100,
            maxDelay: 1000,
            enableLogging: false,
            logger: { log: vi.fn() },
          },
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();

        const result = await resultPromise;
        expect(result.failed).toBe(1);
        expect(callCount).toBe(3); // Initial + 2 retries
      });

      it('should use exponential backoff when response cannot be parsed', async () => {
        let callCount = 0;

        const successResult = {
          batchId: 'batch_123',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };

        mockRequestFn.mockImplementation((_options, callback) => {
          callCount++;
          const statusCode = callCount < 2 ? 503 : 200;
          // First response is unparseable - triggers the catch block in calculateRetryDelay
          const data = callCount < 2 ? 'unparseable-not-json' : successResult;

          const mockResponse = {
            statusCode,
            on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
              if (event === 'data') {
                const responseStr =
                  typeof data === 'string' ? data : JSON.stringify(data);
                setImmediate(() => handler(Buffer.from(responseStr)));
              }
              if (event === 'end') {
                setImmediate(() => handler());
              }
              return mockResponse;
            }),
          };

          const mockReq = {
            on: vi.fn().mockReturnThis(),
            write: vi.fn(),
            end: vi.fn(),
            destroy: vi.fn(),
          };

          if (callback) {
            setImmediate(() => callback(mockResponse));
          }

          return mockReq as unknown as ClientRequest;
        });

        const service = new UploadService(createDefaultOptions());
        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');

        await vi.runAllTimersAsync();

        const result = await resultPromise;
        expect(result.successful).toBe(1);
        expect(callCount).toBe(2); // Initial + 1 retry
      });

      it('should use server-suggested retry delay', async () => {
        let callCount = 0;
        const serverDelay = 2; // 2 seconds

        const successResult = {
          batchId: 'batch_123',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };

        mockRequestFn.mockImplementation((_options, callback) => {
          callCount++;
          const statusCode = callCount < 2 ? 503 : 200;
          const data =
            callCount < 2
              ? { error: { retryAfter: serverDelay } }
              : successResult;

          const mockResponse = {
            statusCode,
            on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
              if (event === 'data') {
                setImmediate(() => handler(Buffer.from(JSON.stringify(data))));
              }
              if (event === 'end') {
                setImmediate(() => handler());
              }
              return mockResponse;
            }),
          };

          const mockReq = {
            on: vi.fn().mockReturnThis(),
            write: vi.fn(),
            end: vi.fn(),
            destroy: vi.fn(),
          };

          if (callback) {
            setImmediate(() => callback(mockResponse));
          }

          return mockReq as unknown as ClientRequest;
        });

        const logger = { log: vi.fn() };
        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 3,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: true,
            logger: { log: vi.fn() },
          },
          logger,
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();

        await resultPromise;
        expect(callCount).toBe(2);
      });

      it('should log retry attempts when logging enabled', async () => {
        let callCount = 0;

        const successResult = {
          batchId: 'batch_123',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };

        mockRequestFn.mockImplementation((_options, callback) => {
          callCount++;
          const statusCode = callCount < 2 ? 503 : 200;
          const data = callCount < 2 ? { error: {} } : successResult;

          const mockResponse = {
            statusCode,
            on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
              if (event === 'data') {
                setImmediate(() => handler(Buffer.from(JSON.stringify(data))));
              }
              if (event === 'end') {
                setImmediate(() => handler());
              }
              return mockResponse;
            }),
          };

          const mockReq = {
            on: vi.fn().mockReturnThis(),
            write: vi.fn(),
            end: vi.fn(),
            destroy: vi.fn(),
          };

          if (callback) {
            setImmediate(() => callback(mockResponse));
          }

          return mockReq as unknown as ClientRequest;
        });

        const logger = { log: vi.fn() };
        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 3,
            baseDelay: 100,
            maxDelay: 1000,
            enableLogging: true,
            logger: { log: vi.fn() },
          },
          logger,
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();

        await resultPromise;

        const logCalls = (logger.log as Mock).mock.calls.map((call) => call[0] as string);
        expect(logCalls.some((msg) => msg.includes('Retry attempt'))).toBe(true);
      });
    });

    describe('aggregation', () => {
      it('should aggregate results from multiple batches', async () => {
        let callCount = 0;

        mockRequestFn.mockImplementation((_options, callback) => {
          callCount++;
          const batchResult = {
            batchId: `batch_${callCount}`,
            successful: 25,
            failed: 0,
            created: Array(25)
              .fill(null)
              .map((_, i) => ({
                packageId: `pkg_${callCount}_${i}`,
                index: i,
              })),
          };

          const mockResponse = {
            statusCode: 200,
            on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
              if (event === 'data') {
                setImmediate(() => handler(Buffer.from(JSON.stringify(batchResult))));
              }
              if (event === 'end') {
                setImmediate(() => handler());
              }
              return mockResponse;
            }),
          };

          const mockReq = {
            on: vi.fn().mockReturnThis(),
            write: vi.fn(),
            end: vi.fn(),
            destroy: vi.fn(),
          };

          if (callback) {
            setImmediate(() => callback(mockResponse));
          }

          return mockReq as unknown as ClientRequest;
        });

        const options = createDefaultOptions({ maxBatchSize: 25 });
        const service = new UploadService(options);

        const builders = Array(100)
          .fill(null)
          .map(() => createMockBuilder());
        const resultPromise = service.sendCapsas(builders, 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.successful).toBe(100); // 25 * 4
        expect(result.created).toHaveLength(100);
        expect(callCount).toBe(4);
      });

      it('should include errors from all batches', async () => {
        let callCount = 0;

        mockRequestFn.mockImplementation((_options, callback) => {
          callCount++;
          const batchResult = {
            batchId: `batch_${callCount}`,
            successful: 24,
            failed: 1,
            partialSuccess: true,
            created: Array(24)
              .fill(null)
              .map((_, i) => ({
                packageId: `pkg_${callCount}_${i}`,
                index: i,
              })),
            errors: [{ index: 24, packageId: `pkg_${callCount}_24`, error: 'Failed' }],
          };

          const mockResponse = {
            statusCode: 207,
            on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
              if (event === 'data') {
                setImmediate(() => handler(Buffer.from(JSON.stringify(batchResult))));
              }
              if (event === 'end') {
                setImmediate(() => handler());
              }
              return mockResponse;
            }),
          };

          const mockReq = {
            on: vi.fn().mockReturnThis(),
            write: vi.fn(),
            end: vi.fn(),
            destroy: vi.fn(),
          };

          if (callback) {
            setImmediate(() => callback(mockResponse));
          }

          return mockReq as unknown as ClientRequest;
        });

        const options = createDefaultOptions({ maxBatchSize: 25 });
        const service = new UploadService(options);

        const builders = Array(50)
          .fill(null)
          .map(() => createMockBuilder());
        const resultPromise = service.sendCapsas(builders, 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.successful).toBe(48); // 24 * 2
        expect(result.failed).toBe(2); // 1 * 2
        expect(result.partialSuccess).toBe(true);
        expect(result.errors).toHaveLength(2);
      });

      it('should adjust indices for multi-batch results', async () => {
        let callCount = 0;

        mockRequestFn.mockImplementation((_options, callback) => {
          callCount++;
          const batchResult = {
            batchId: `batch_${callCount}`,
            successful: 5,
            failed: 0,
            created: Array(5)
              .fill(null)
              .map((_, i) => ({
                packageId: `pkg_${callCount}_${i}`,
                index: i, // 0-4 in each batch
              })),
          };

          const mockResponse = {
            statusCode: 200,
            on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
              if (event === 'data') {
                setImmediate(() => handler(Buffer.from(JSON.stringify(batchResult))));
              }
              if (event === 'end') {
                setImmediate(() => handler());
              }
              return mockResponse;
            }),
          };

          const mockReq = {
            on: vi.fn().mockReturnThis(),
            write: vi.fn(),
            end: vi.fn(),
            destroy: vi.fn(),
          };

          if (callback) {
            setImmediate(() => callback(mockResponse));
          }

          return mockReq as unknown as ClientRequest;
        });

        const options = createDefaultOptions({ maxBatchSize: 5 });
        const service = new UploadService(options);

        const builders = Array(10)
          .fill(null)
          .map(() => createMockBuilder());
        const resultPromise = service.sendCapsas(builders, 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        // First batch: indices 0-4, Second batch: indices 5-9
        const indices = result.created.map((c) => c.index);
        expect(indices).toContain(0);
        expect(indices).toContain(4);
        expect(indices).toContain(5);
        expect(indices).toContain(9);
      });
    });
  });
  describe('token refresh on 401', () => {
    const sent: SendResult = { batchId: 'batch_1', successful: 1, failed: 0, created: [{ packageId: 'pkg_1', index: 0, createdAt: '2026-01-01T00:00:00Z' }] };

    function createRefresher(overrides: Partial<TokenRefresher> = {}): TokenRefresher {
      return {
        refresh: vi.fn().mockResolvedValue(true),
        canRefresh: vi.fn().mockReturnValue(true),
        getToken: vi.fn().mockReturnValue('new-token'),
        getLastRefreshError: vi.fn().mockReturnValue(null),
        ...overrides,
      };
    }

    function sentAuthHeaders(): string[] {
      return mockRequestFn.mock.calls.map(([options]) => (options as { headers: Record<string, string> }).headers.Authorization!);
    }

    async function send(service: UploadService): Promise<SendResult> {
      const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
      await vi.runAllTimersAsync();
      return resultPromise;
    }

    it('refreshes and resends with the new token', async () => {
      setupMockRequest([{ statusCode: 401, data: { error: { code: 'UNAUTHORIZED' } } }, { statusCode: 200, data: sent }]);
      let token = 'old-token';
      const tokenRefresher = createRefresher({ refresh: vi.fn().mockImplementation(async () => { token = 'new-token'; return true; }) });
      const service = new UploadService(createDefaultOptions({ getToken: () => token, tokenRefresher }));

      const result = await send(service);

      expect(result.successful).toBe(1);
      expect(tokenRefresher.refresh).toHaveBeenCalledTimes(1);
      expect(sentAuthHeaders()).toEqual(['Bearer old-token', 'Bearer new-token']);
    });

    it('reports the refresh error when the refresh fails', async () => {
      setupMockRequest({ statusCode: 401, data: { error: { code: 'UNAUTHORIZED' } } });
      const tokenRefresher = createRefresher({
        refresh: vi.fn().mockResolvedValue(false),
        getLastRefreshError: vi.fn().mockReturnValue(new Error('Invalid or expired refresh token')),
      });
      const service = new UploadService(createDefaultOptions({ tokenRefresher }));

      const result = await send(service);

      expect(result.failed).toBe(1);
      expect(result.errors?.[0]?.error).toContain('Invalid or expired refresh token');
      expect(mockRequestFn).toHaveBeenCalledTimes(1);
    });

    it('does not refresh a second time when the resent request is also rejected', async () => {
      setupMockRequest({ statusCode: 401, data: { error: { code: 'UNAUTHORIZED', message: 'Still unauthorized' } } });
      const tokenRefresher = createRefresher();
      const service = new UploadService(createDefaultOptions({ tokenRefresher }));

      const result = await send(service);

      expect(result.failed).toBe(1);
      expect(tokenRefresher.refresh).toHaveBeenCalledTimes(1);
      expect(mockRequestFn).toHaveBeenCalledTimes(2);
    });

    it('does not refresh when there is no refresh token', async () => {
      setupMockRequest({ statusCode: 401, data: { error: { code: 'UNAUTHORIZED' } } });
      const tokenRefresher = createRefresher({ canRefresh: vi.fn().mockReturnValue(false) });
      const service = new UploadService(createDefaultOptions({ tokenRefresher }));

      const result = await send(service);

      expect(result.failed).toBe(1);
      expect(tokenRefresher.refresh).not.toHaveBeenCalled();
      expect(mockRequestFn).toHaveBeenCalledTimes(1);
    });

    it('still retries a 503 after refreshing', async () => {
      setupMockRequest([
        { statusCode: 401, data: { error: { code: 'UNAUTHORIZED' } } },
        { statusCode: 503, data: { error: { code: 'SERVICE_UNAVAILABLE' } } },
        { statusCode: 200, data: sent },
      ]);
      const tokenRefresher = createRefresher();
      const service = new UploadService(createDefaultOptions({ tokenRefresher }));

      const result = await send(service);

      expect(result.successful).toBe(1);
      expect(tokenRefresher.refresh).toHaveBeenCalledTimes(1);
      expect(mockRequestFn).toHaveBeenCalledTimes(3);
    });
  });

});

describe('UploadService send results', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  /** Builder whose built capsa carries a known packageId. */
  function builderWithId(packageId: string, buildError?: Error): CapsaBuilder {
    return {
      getFileCount: vi.fn().mockReturnValue(1),
      getRecipientIds: vi.fn().mockReturnValue(['recipient_1']),
      build: buildError
        ? vi.fn().mockRejectedValue(buildError)
        : vi.fn().mockResolvedValue({
            capsa: { packageId },
            files: [{ data: Buffer.from('x'), metadata: { fileId: `file_${packageId}.enc` } }],
          }),
    } as unknown as CapsaBuilder;
  }

  function noRetryOptions(overrides?: Partial<UploadServiceOptions>): UploadServiceOptions {
    return createDefaultOptions({
      retryConfig: { maxRetries: 0, baseDelay: 1000, maxDelay: 30000, enableLogging: false, logger: { log: vi.fn() } },
      ...overrides,
    });
  }

  async function send(service: UploadService, builders: CapsaBuilder[]): Promise<SendResult> {
    const promise = service.sendCapsas(builders, 'creator_123');
    await vi.runAllTimersAsync();
    return promise;
  }

  it('maps created and errors by request position, with the server code', async () => {
    // Capsa 0 fails, capsa 1 succeeds: created[0].index must be 1, not 0
    setupMockRequest({
      statusCode: 207,
      data: {
        success: true,
        successful: 1,
        failed: 1,
        batchId: 'batch_1',
        created: [{ index: 1, packageId: 'capsa_b', createdAt: '2026-11-08T10:00:00.000Z' }],
        errors: [{ index: 0, packageId: 'capsa_a', code: 'SIGNATURE_INVALID', message: 'Signature does not verify' }],
      },
    });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a'), builderWithId('capsa_b')]);

    expect(result.batchId).toBe('batch_1');
    expect(result.created).toStrictEqual([{ index: 1, packageId: 'capsa_b', createdAt: '2026-11-08T10:00:00.000Z' }]);
    expect(result.errors).toEqual([
      { index: 0, packageId: 'capsa_a', code: 'SIGNATURE_INVALID', error: 'Signature does not verify' },
    ]);
    expect(result.successful).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.partialSuccess).toBe(true);
  });

  it('surfaces idempotency conflicts per capsa without retrying', async () => {
    setupMockRequest({
      statusCode: 207,
      data: {
        created: [{ index: 2, packageId: 'capsa_c', createdAt: '2026-01-01T00:00:00.000Z' }],
        errors: [
          { index: 0, packageId: 'capsa_a', code: 'ENVELOPE_ALREADY_EXISTS', message: 'Exists' },
          { index: 1, packageId: 'capsa_b', code: 'ENVELOPE_CREATION_IN_PROGRESS', message: 'In progress' },
        ],
      },
    });

    const result = await send(new UploadService(createDefaultOptions()), [
      builderWithId('capsa_a'), builderWithId('capsa_b'), builderWithId('capsa_c'),
    ]);

    expect(result.errors?.map(e => e.code)).toEqual(['ENVELOPE_ALREADY_EXISTS', 'ENVELOPE_CREATION_IN_PROGRESS']);
    expect(result.created[0]?.createdAt).toBe('2026-01-01T00:00:00.000Z');
    expect(mockRequestFn).toHaveBeenCalledTimes(1);
  });

  it('reports a 201 with every capsa created', async () => {
    setupMockRequest({
      statusCode: 201,
      data: { success: true, successful: 2, failed: 0, created: [{ index: 0, packageId: 'capsa_a' }, { index: 1, packageId: 'capsa_b' }], errors: [] },
    });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a'), builderWithId('capsa_b')]);

    expect(result.created.map(c => c.index)).toEqual([0, 1]);
    expect(result.errors).toBeUndefined();
    expect(result.partialSuccess).toBe(false);
  });

  it('surfaces an all-fail 422 as per-capsa failures, not a thrown error', async () => {
    setupMockRequest({
      statusCode: 422,
      data: {
        success: false,
        successful: 0,
        failed: 2,
        created: [],
        errors: [
          { index: 0, packageId: 'capsa_a', code: 'KEYCHAIN_SINGLE_PRINCIPAL_REQUIRED', message: 'One principal' },
          { index: 1, packageId: 'capsa_b', code: 'DELEGATE_PRINCIPAL_MISMATCH', message: 'Wrong principal' },
        ],
      },
    });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a'), builderWithId('capsa_b')]);

    expect(result.successful).toBe(0);
    expect(result.failed).toBe(2);
    expect(result.errors?.map(e => [e.index, e.code])).toEqual([
      [0, 'KEYCHAIN_SINGLE_PRINCIPAL_REQUIRED'],
      [1, 'DELEGATE_PRINCIPAL_MISMATCH'],
    ]);
    expect(mockRequestFn).toHaveBeenCalledTimes(1);
  });

  it('treats a 422 in the standard error shape as a request failure with its code', async () => {
    setupMockRequest({ statusCode: 422, data: { error: { code: 'UNPROCESSABLE', message: 'Nope' } } });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a')]);

    expect(result.errors).toEqual([{ index: 0, packageId: 'capsa_a', code: 'UNPROCESSABLE', error: 'Nope' }]);
  });

  it('treats a non-JSON 422 as a request failure with HTTP_422', async () => {
    setupMockRequest({ statusCode: 422, data: 'not json' });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a')]);

    expect(result.errors?.[0]?.code).toBe('HTTP_422');
  });

  it('defaults a per-capsa failure with no code or message', async () => {
    setupMockRequest({ statusCode: 422, data: { success: false, created: [], errors: [{ index: 0 }] } });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a')]);

    expect(result.errors).toEqual([{ index: 0, code: 'UNKNOWN_ERROR', error: 'Capsa was not created' }]);
  });

  it('adds the chunk offset so indexes are positions in the caller array', async () => {
    let call = 0;
    mockRequestFn.mockImplementation((_options, callback) => {
      call++;
      const body = call === 1
        ? { created: [{ index: 0, packageId: 'capsa_a' }, { index: 1, packageId: 'capsa_b' }] }
        : { created: [], errors: [{ index: 0, packageId: 'capsa_c', code: 'FILE_HASH_MISMATCH', message: 'Hash' }] };
      return respondWith(callback, call === 1 ? 201 : 422, body);
    });

    const result = await send(
      new UploadService(noRetryOptions({ maxBatchSize: 2 })),
      [builderWithId('capsa_a'), builderWithId('capsa_b'), builderWithId('capsa_c')]
    );

    expect(result.created.map(c => c.index)).toEqual([0, 1]);
    expect(result.errors).toEqual([{ index: 2, packageId: 'capsa_c', code: 'FILE_HASH_MISMATCH', error: 'Hash' }]);
  });

  it('fails only the builder that cannot build; the rest of its chunk is sent', async () => {
    setupMockRequest({
      statusCode: 201,
      data: { created: [{ index: 0, packageId: 'capsa_a' }, { index: 1, packageId: 'capsa_c' }] },
    });

    const result = await send(new UploadService(noRetryOptions()), [
      builderWithId('capsa_a'),
      builderWithId('capsa_b', new Error('Expiration is required')),
      builderWithId('capsa_c'),
    ]);

    // Request position 1 is the caller's builder 2
    expect(result.created).toEqual([
      { index: 0, packageId: 'capsa_a' },
      { index: 2, packageId: 'capsa_c' },
    ]);
    expect(result.errors).toEqual([{ index: 1, code: 'BUILD_FAILED', error: 'Expiration is required' }]);
    expect(mockRequestFn).toHaveBeenCalledTimes(1);
  });

  it('keeps the code of an SDK error thrown by build', async () => {
    const buildError = new CapsaraError('Too many keys', 'KEYCHAIN_TOO_LARGE', 0);
    setupMockRequest({ statusCode: 201, data: { created: [] } });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a', buildError)]);

    expect(result.errors?.[0]?.code).toBe('KEYCHAIN_TOO_LARGE');
  });

  it('fails only the capsa whose recipient has no key, with RECIPIENT_KEY_NOT_FOUND', async () => {
    setupMockRequest({ statusCode: 201, data: { created: [{ index: 0, packageId: 'capsa_b' }] } });
    const noKey = new CapsaraError('Recipient party_x has no registered public key', 'RECIPIENT_KEY_NOT_FOUND', 0, { partyId: 'party_x' });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a', noKey), builderWithId('capsa_b')]);

    expect(result.errors).toEqual([
      { index: 0, code: 'RECIPIENT_KEY_NOT_FOUND', error: 'Recipient party_x has no registered public key' },
    ]);
    expect(result.created).toEqual([{ index: 1, packageId: 'capsa_b' }]);
  });

  it('sends nothing when every builder in a chunk fails to build', async () => {
    const result = await send(new UploadService(noRetryOptions()), [
      builderWithId('capsa_a', new Error('bad')),
    ]);

    expect(result.failed).toBe(1);
    expect(mockRequestFn).not.toHaveBeenCalled();
  });

  it('records a non-Error build rejection', async () => {
    const builder = builderWithId('capsa_a');
    (builder.build as Mock).mockRejectedValue('weird');

    const result = await send(new UploadService(noRetryOptions()), [builder]);

    expect(result.errors).toEqual([{ index: 0, code: 'BUILD_FAILED', error: 'weird' }]);
  });

  it('fails the whole chunk with the key lookup error when party keys cannot be fetched', async () => {
    const options = noRetryOptions({ maxBatchSize: 1 });
    (options.keyManager.fetchPartyKeys as Mock)
      .mockRejectedValueOnce(new CapsaraError('Party lookup failed', 'SERVICE_UNAVAILABLE', 503))
      .mockResolvedValue([]);
    setupMockRequest({ statusCode: 201, data: { created: [{ index: 0, packageId: 'capsa_b' }] } });

    const result = await send(new UploadService(options), [builderWithId('capsa_a'), builderWithId('capsa_b')]);

    expect(result.errors).toEqual([{ index: 0, code: 'SERVICE_UNAVAILABLE', error: 'Party lookup failed' }]);
    expect(result.created).toEqual([{ index: 1, packageId: 'capsa_b' }]);
  });

  it('only fails the request that failed when a chunk is split by size', async () => {
    let call = 0;
    mockRequestFn.mockImplementation((_options, callback) => {
      call++;
      return call === 1
        ? respondWith(callback, 201, { created: [{ index: 0, packageId: 'capsa_a' }] })
        : respondWith(callback, 413, { error: { code: 'REQUEST_TOO_LARGE', message: 'Too large' } });
    });
    const options = noRetryOptions({
      getLimits: async () => ({ maxFileSize: 1, maxFilesPerCapsa: 500, maxTotalSize: 1, maxRequestSize: 1 }),
    });

    const result = await send(new UploadService(options), [builderWithId('capsa_a'), builderWithId('capsa_b')]);

    // The accepted first request must not be reported as failed
    expect(result.created).toEqual([{ index: 0, packageId: 'capsa_a' }]);
    expect(result.errors).toEqual([{ index: 1, packageId: 'capsa_b', code: 'REQUEST_TOO_LARGE', error: 'Too large' }]);
  });

  it('keeps the server code, details and retryAfter of a batch-level error', async () => {
    setupMockRequest({
      statusCode: 409,
      data: { error: { code: 'ENVELOPE_ALREADY_EXISTS', message: 'Already exists', details: { packageId: 'capsa_a' } } },
    });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a')]);

    expect(result.errors).toEqual([{ index: 0, packageId: 'capsa_a', code: 'ENVELOPE_ALREADY_EXISTS', error: 'Already exists' }]);
  });

  it('reports NETWORK_ERROR for a transport failure', async () => {
    setupMockRequestWithError('ECONNRESET');

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a')]);

    expect(result.errors?.[0]).toMatchObject({ code: 'NETWORK_ERROR', error: expect.stringContaining('ECONNRESET') });
  });

  it('reports UPLOAD_TIMEOUT for a timeout', async () => {
    setupMockRequestWithTimeout();

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a')]);

    expect(result.errors?.[0]?.code).toBe('UPLOAD_TIMEOUT');
  });

  it('reports INVALID_RESPONSE for an unparseable success body', async () => {
    setupMockRequest({ statusCode: 201, data: 'not json' });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a')]);

    expect(result.errors?.[0]?.code).toBe('INVALID_RESPONSE');
  });

  it.each([
    ['JSON null', null],
    ['a number', 7],
    ['a string', 'created'],
    ['an array', [{ index: 0, packageId: 'capsa_a' }]],
  ])('reports INVALID_RESPONSE for every capsa when a success body is %s', async (_label, body) => {
    setupMockRequest({ statusCode: 201, data: JSON.stringify(body) });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a'), builderWithId('capsa_b')]);

    expect(result.created).toEqual([]);
    expect(result.errors?.map(e => [e.index, e.code])).toEqual([
      [0, 'INVALID_RESPONSE'],
      [1, 'INVALID_RESPONSE'],
    ]);
  });

  it('fails every capsa of the request with INVALID_RESPONSE when an index is out of range', async () => {
    setupMockRequest({
      statusCode: 207,
      data: {
        created: [{ index: 7, packageId: 'capsa_b' }],
        errors: [{ index: 0, code: 'X', message: 'lost' }],
      },
    });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a'), builderWithId('capsa_b')]);

    expect(result.created).toEqual([]);
    expect(result.errors?.map(e => [e.index, e.packageId, e.code])).toEqual([
      [0, 'capsa_a', 'INVALID_RESPONSE'],
      [1, 'capsa_b', 'INVALID_RESPONSE'],
    ]);
  });

  it('does not match by packageId when the index is missing', async () => {
    setupMockRequest({ statusCode: 201, data: { created: [{ packageId: 'capsa_a' }] } });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a')]);

    expect(result.created).toEqual([]);
    expect(result.errors).toEqual([
      { index: 0, packageId: 'capsa_a', code: 'INVALID_RESPONSE', error: expect.stringContaining('index') },
    ]);
  });

  it('treats a duplicate index as an invalid response', async () => {
    setupMockRequest({
      statusCode: 201,
      data: { created: [{ index: 0, packageId: 'capsa_a' }, { index: 0, packageId: 'capsa_b' }] },
    });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a'), builderWithId('capsa_b')]);

    expect(result.successful).toBe(0);
    expect(result.errors?.every(e => e.code === 'INVALID_RESPONSE')).toBe(true);
  });

  it('reports a capsa the response leaves out as INVALID_RESPONSE and keeps the rest', async () => {
    setupMockRequest({ statusCode: 201, data: { created: [{ index: 1, packageId: 'capsa_b' }] } });

    const result = await send(new UploadService(noRetryOptions()), [builderWithId('capsa_a'), builderWithId('capsa_b')]);

    expect(result.created).toEqual([{ index: 1, packageId: 'capsa_b' }]);
    expect(result.errors).toEqual([
      { index: 0, packageId: 'capsa_a', code: 'INVALID_RESPONSE', error: 'Send response did not report this capsa' },
    ]);
  });

  it('drops a builder that fails during a keychain rebuild and sends the rest', async () => {
    const mismatch = { error: { code: 'KEYCHAIN_KEY_OUTDATED', message: 'Key outdated' } };
    let call = 0;
    mockRequestFn.mockImplementation((_options, callback) => {
      call++;
      return call === 1
        ? respondWith(callback, 409, mismatch)
        : respondWith(callback, 201, { created: [{ index: 0, packageId: 'capsa_b' }] });
    });
    const failing = builderWithId('capsa_a');
    (failing.build as Mock)
      .mockResolvedValueOnce({ capsa: { packageId: 'capsa_a' }, files: [] })
      .mockRejectedValueOnce(new Error('Recipient has no key'));

    const result = await send(new UploadService(noRetryOptions()), [failing, builderWithId('capsa_b')]);

    expect(result.created).toEqual([{ index: 1, packageId: 'capsa_b' }]);
    expect(result.errors).toEqual([{ index: 0, code: 'BUILD_FAILED', error: 'Recipient has no key' }]);
  });

  it('keeps sending later requests after a middle request fails and reports only its capsas', async () => {
    let call = 0;
    mockRequestFn.mockImplementation((_options, callback) => {
      call++;
      if (call === 2) {
        return respondWith(callback, 400, { error: { code: 'INVALID_FILE', message: 'Bad file part' } });
      }
      return respondWith(callback, 201, { created: [{ index: 0, packageId: call === 1 ? 'capsa_a' : 'capsa_c' }] });
    });
    const options = noRetryOptions({
      getLimits: async () => ({ maxFileSize: 1, maxFilesPerCapsa: 500, maxTotalSize: 1, maxRequestSize: 1 }),
    });

    const result = await send(new UploadService(options), [builderWithId('capsa_a'), builderWithId('capsa_b'), builderWithId('capsa_c')]);

    expect(mockRequestFn).toHaveBeenCalledTimes(3);
    expect(result.created).toEqual([
      { index: 0, packageId: 'capsa_a' },
      { index: 2, packageId: 'capsa_c' },
    ]);
    expect(result.errors).toEqual([{ index: 1, packageId: 'capsa_b', code: 'INVALID_FILE', error: 'Bad file part' }]);
  });

  it('keeps sending later chunks after a chunk fails at request level', async () => {
    let call = 0;
    mockRequestFn.mockImplementation((_options, callback) => {
      call++;
      return call === 1
        ? respondWith(callback, 413, { error: { code: 'REQUEST_TOO_LARGE', message: 'Too large' } })
        : respondWith(callback, 201, { created: [{ index: 0, packageId: 'capsa_b' }] });
    });

    const result = await send(new UploadService(noRetryOptions({ maxBatchSize: 1 })), [builderWithId('capsa_a'), builderWithId('capsa_b')]);

    expect(result.created).toEqual([{ index: 1, packageId: 'capsa_b' }]);
    expect(result.errors?.map(e => [e.index, e.code])).toEqual([[0, 'REQUEST_TOO_LARGE']]);
  });

  it('returns only rebuild failures when no builder survives a rebuild', async () => {
    setupMockRequest({ statusCode: 409, data: { error: { code: 'KEYCHAIN_DELEGATES_MISMATCH', message: 'Moved' } } });
    const builder = builderWithId('capsa_a');
    (builder.build as Mock)
      .mockResolvedValueOnce({ capsa: { packageId: 'capsa_a' }, files: [] })
      .mockRejectedValueOnce(new Error('gone'));

    const result = await send(new UploadService(noRetryOptions()), [builder]);

    expect(result.errors).toEqual([{ index: 0, code: 'BUILD_FAILED', error: 'gone' }]);
    expect(mockRequestFn).toHaveBeenCalledTimes(1);
  });
});

type UploadStep =
  | { kind: 'status'; statusCode: number; body: unknown; headers?: Record<string, string> }
  | { kind: 'error'; code: string }
  | { kind: 'timeout' };

function setupUploadSteps(steps: UploadStep[]): void {
  let call = 0;
  mockRequestFn.mockImplementation((_options, callback?: (res: unknown) => void) => {
    const step = steps[Math.min(call, steps.length - 1)]!;
    call++;
    const handlers: Record<string, (arg?: unknown) => void> = {};
    const mockReq = {
      on: vi.fn((event: string, handler: (arg?: unknown) => void) => {
        handlers[event] = handler;
        return mockReq;
      }),
      write: vi.fn(),
      end: vi.fn(() => {
        setImmediate(() => {
          if (step.kind === 'error') {
            const err = Object.assign(new Error(`connect ${step.code}`), { code: step.code });
            handlers.error?.(err);
          } else if (step.kind === 'timeout') {
            handlers.timeout?.();
            handlers.error?.(Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }));
          } else {
            const res = {
              statusCode: step.statusCode,
              headers: step.headers ?? {},
              on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
                if (event === 'data') setImmediate(() => handler(Buffer.from(JSON.stringify(step.body))));
                if (event === 'end') setImmediate(() => handler());
                return res;
              }),
            };
            callback?.(res);
          }
        });
      }),
      destroy: vi.fn(),
    };
    return mockReq as unknown as ClientRequest;
  });
}

describe('UploadService retry policy', () => {
  const created = { created: [{ index: 0, packageId: 'capsa_a', createdAt: '2026-01-01T00:00:00.000Z' }] };

  function builder(): CapsaBuilder {
    return {
      getFileCount: vi.fn().mockReturnValue(1),
      getRecipientIds: vi.fn().mockReturnValue(['recipient_1']),
      build: vi.fn().mockResolvedValue({
        capsa: { packageId: 'capsa_a' },
        files: [{ data: Buffer.from('x'), metadata: { fileId: 'file_a.enc' } }],
      }),
    } as unknown as CapsaBuilder;
  }

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('resends the POST after a dropped connection', async () => {
    setupUploadSteps([{ kind: 'error', code: 'ECONNRESET' }, { kind: 'status', statusCode: 201, body: created }]);

    const promise = new UploadService(createDefaultOptions()).sendCapsas([builder()], 'creator_123');
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(mockRequestFn).toHaveBeenCalledTimes(2);
    expect(result.created.map(c => c.packageId)).toEqual(['capsa_a']);
  });

  it('gives up after three retries of a dropped connection with NETWORK_ERROR', async () => {
    setupUploadSteps([{ kind: 'error', code: 'ECONNREFUSED' }]);

    const promise = new UploadService(createDefaultOptions()).sendCapsas([builder()], 'creator_123');
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(mockRequestFn).toHaveBeenCalledTimes(4);
    expect(result.errors?.[0]).toMatchObject({ code: 'NETWORK_ERROR', error: expect.stringContaining('ECONNREFUSED') });
  });

  it('does not resend after a transport error that is not a dropped connection', async () => {
    setupUploadSteps([{ kind: 'error', code: 'CERT_HAS_EXPIRED' }, { kind: 'status', statusCode: 201, body: created }]);

    const promise = new UploadService(createDefaultOptions()).sendCapsas([builder()], 'creator_123');
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(mockRequestFn).toHaveBeenCalledTimes(1);
    expect(result.errors?.[0]?.code).toBe('NETWORK_ERROR');
  });

  it('does not resend a POST whose connection attempt timed out', async () => {
    setupUploadSteps([{ kind: 'error', code: 'ETIMEDOUT' }, { kind: 'status', statusCode: 201, body: created }]);

    const promise = new UploadService(createDefaultOptions()).sendCapsas([builder()], 'creator_123');
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(mockRequestFn).toHaveBeenCalledTimes(1);
    expect(result.errors?.[0]?.code).toBe('NETWORK_ERROR');
  });

  it('does not resend a POST that timed out, even when the socket then errors', async () => {
    setupUploadSteps([{ kind: 'timeout' }, { kind: 'status', statusCode: 201, body: created }]);

    const promise = new UploadService(createDefaultOptions()).sendCapsas([builder()], 'creator_123');
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(mockRequestFn).toHaveBeenCalledTimes(1);
    expect(result.errors?.[0]?.code).toBe('UPLOAD_TIMEOUT');
  });

  it('retries a 429 without a hint using backoff', async () => {
    setupUploadSteps([
      { kind: 'status', statusCode: 429, body: { error: { code: 'RATE_LIMITED', message: 'Slow down' } } },
      { kind: 'status', statusCode: 201, body: created },
    ]);

    const promise = new UploadService(createDefaultOptions()).sendCapsas([builder()], 'creator_123');
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(mockRequestFn).toHaveBeenCalledTimes(2);
    expect(result.successful).toBe(1);
  });

  it('caps a long server hint at 30 seconds', async () => {
    setupUploadSteps([
      { kind: 'status', statusCode: 503, body: { error: { code: 'SERVICE_UNAVAILABLE', message: 'Busy', retryAfter: 600 } } },
      { kind: 'status', statusCode: 201, body: created },
    ]);

    const promise = new UploadService(createDefaultOptions()).sendCapsas([builder()], 'creator_123');
    await vi.advanceTimersByTimeAsync(29_000);
    expect(mockRequestFn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(mockRequestFn).toHaveBeenCalledTimes(2);
    await vi.runAllTimersAsync();
    await expect(promise).resolves.toMatchObject({ successful: 1 });
  });

  it('honours the Retry-After header when the body has no hint', async () => {
    setupUploadSteps([
      { kind: 'status', statusCode: 503, body: { error: { code: 'SERVICE_UNAVAILABLE', message: 'Busy' } }, headers: { 'retry-after': '7' } },
      { kind: 'status', statusCode: 201, body: created },
    ]);

    const promise = new UploadService(createDefaultOptions()).sendCapsas([builder()], 'creator_123');
    await vi.advanceTimersByTimeAsync(6_900);
    expect(mockRequestFn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(200);
    expect(mockRequestFn).toHaveBeenCalledTimes(2);
    await vi.runAllTimersAsync();
    await expect(promise).resolves.toMatchObject({ successful: 1 });
  });

  it('does not retry a 500', async () => {
    setupUploadSteps([{ kind: 'status', statusCode: 500, body: { error: { code: 'INTERNAL_ERROR', message: 'Oops' } } }]);

    const promise = new UploadService(createDefaultOptions()).sendCapsas([builder()], 'creator_123');
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(mockRequestFn).toHaveBeenCalledTimes(1);
    expect(result.errors?.[0]?.code).toBe('INTERNAL_ERROR');
  });
});

/** Respond to a mocked http.request with a status and JSON body. */
function respondWith(
  callback: ((res: unknown) => void) | undefined,
  statusCode: number,
  body: unknown
): ClientRequest {
  const mockResponse = {
    statusCode,
    on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
      if (event === 'data') {
        setImmediate(() => handler(Buffer.from(JSON.stringify(body))));
      }
      if (event === 'end') {
        setImmediate(() => handler());
      }
      return mockResponse;
    }),
  };
  const mockReq = { on: vi.fn().mockReturnThis(), write: vi.fn(), end: vi.fn(), destroy: vi.fn() };
  if (callback) {
    setImmediate(() => callback(mockResponse));
  }
  return mockReq as unknown as ClientRequest;
}
