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
    Agent: vi.fn().mockImplementation(() => ({
      maxSockets: 10,
      keepAlive: true,
      destroy: vi.fn(),
    })),
  };
});

vi.mock('https', async (importOriginal) => {
  const actual = await importOriginal<typeof import('https')>();
  return {
    ...actual,
    request: mockRequestFn,
    Agent: vi.fn().mockImplementation(() => ({
      maxSockets: 10,
      keepAlive: true,
      destroy: vi.fn(),
    })),
  };
});

// Mock the multipart builder
vi.mock('../../../../src/internal/upload/multipart-builder.js', () => ({
  CapsasMultipartBuilder: vi.fn().mockImplementation(() => ({
    addMetadata: vi.fn().mockReturnThis(),
    addCapsaMetadata: vi.fn().mockReturnThis(),
    addFileBinary: vi.fn().mockReturnThis(),
    build: vi.fn().mockReturnValue(Buffer.from('mock-multipart-body')),
    getContentType: vi.fn().mockReturnValue('multipart/form-data; boundary=----MockBoundary'),
  })),
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
import type { KeyManager } from '../../../../src/internal/services/key-service.js';

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
      requestTimeout: 60000,
      uploadTimeout: 120000,
      downloadTimeout: 30000,
      maxSockets: 50,
      keepAlive: true,
    },
    retryConfig: {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 30000,
      enableLogging: false,
    },
    logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
    maxBatchSize: 100,
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
    });

    describe('successful upload', () => {
      it('should send single capsa successfully', async () => {
        const mockResult: SendResult = {
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
        const mockResult: SendResult = {
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

      it('should handle 207 multi-status response', async () => {
        const mockResult: SendResult = {
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
        const batch1Result: SendResult = {
          batchId: 'batch_1',
          successful: 50,
          failed: 0,
          created: Array(50)
            .fill(null)
            .map((_, i) => ({ packageId: `pkg_${i}`, index: i })),
        };
        const batch2Result: SendResult = {
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
        const batch1Result: SendResult = {
          batchId: 'batch_1',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };
        const batch2Result: SendResult = {
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

      it('should log batch information when logging enabled', async () => {
        const mockResult: SendResult = {
          batchId: 'batch_123',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };
        setupMockRequest({ statusCode: 200, data: mockResult });

        const logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() };
        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 3,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: true,
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
        const batch2Result: SendResult = {
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
        const batch2Result: SendResult = {
          batchId: 'batch_2',
          successful: 1,
          failed: 0,
          created: [{ packageId: 'pkg_1', index: 0 }],
        };
        setupMockRequest([
          { statusCode: 500, data: { error: 'Server error' } },
          { statusCode: 200, data: batch2Result },
        ]);

        const logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() };
        const options = createDefaultOptions({
          maxBatchSize: 1,
          retryConfig: {
            maxRetries: 0,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: true,
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
          },
        });
        const service = new UploadService(options);

        const resultPromise = service.sendCapsas([createMockBuilder()], 'creator_123');
        await vi.runAllTimersAsync();
        const result = await resultPromise;

        expect(result.failed).toBe(1);
        expect(result.errors?.[0]?.error).toContain('status 400');
        // Should not retry for 400
        expect(mockRequestFn).toHaveBeenCalledTimes(1);
      });

      it('should handle request timeout', async () => {
        setupMockRequestWithTimeout();

        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 0,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: false,
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

    describe('retry logic', () => {
      it('should retry on 503 status', async () => {
        let callCount = 0;

        const successResult: SendResult = {
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

        const successResult: SendResult = {
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

        const successResult: SendResult = {
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

        const successResult: SendResult = {
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

        const logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() };
        const options = createDefaultOptions({
          retryConfig: {
            maxRetries: 3,
            baseDelay: 1000,
            maxDelay: 30000,
            enableLogging: true,
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

        const successResult: SendResult = {
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
          const batchResult: SendResult = {
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
          const batchResult: SendResult = {
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
          const batchResult: SendResult = {
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
});
