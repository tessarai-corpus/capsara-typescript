/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Send (Upload) Operations
 * Tests batch auto-split, empty array error, multipart construction,
 * bearer token, 207 partial success parsing.
 */

import type { ClientRequest } from 'http';

const { mockRequestFn } = vi.hoisted(() => ({
  mockRequestFn: vi.fn(),
}));

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

vi.mock('../../src/internal/upload/multipart-builder.js', () => ({
  CapsasMultipartBuilder: vi.fn().mockImplementation(() => ({
    addMetadata: vi.fn().mockReturnThis(),
    addCapsaMetadata: vi.fn().mockReturnThis(),
    addFileBinary: vi.fn().mockReturnThis(),
    build: vi.fn().mockReturnValue(Buffer.from('mock-body')),
    getContentType: vi.fn().mockReturnValue('multipart/form-data; boundary=----MockBoundary'),
  })),
}));

vi.mock('../../src/internal/config/http-client.js', () => ({
  createAgentForProtocol: vi.fn(() => ({ maxSockets: 10, keepAlive: true })),
}));

import {
  UploadService,
  type UploadServiceOptions,
  type SendResult,
} from '../../src/internal/services/upload-service.js';
import type { CapsaBuilder } from '../../src/builder/capsa-builder.js';
import type { KeyManager } from '../../src/internal/services/key-service.js';

function createMockBuilder(fileCount = 1): CapsaBuilder {
  return {
    getFileCount: vi.fn().mockReturnValue(fileCount),
    getRecipientIds: vi.fn().mockReturnValue(['recipient_1']),
    build: vi.fn().mockResolvedValue({
      capsa: { id: 'capsa_test' },
      files: Array(fileCount).fill(null).map((_, i) => ({
        data: Buffer.from(`file-${i}`),
        metadata: { fileId: `file_${i}.enc` },
      })),
    }),
  } as unknown as CapsaBuilder;
}

function createDefaultOptions(overrides?: Partial<UploadServiceOptions>): UploadServiceOptions {
  return {
    baseUrl: 'https://api.example.com',
    keyManager: {
      fetchPartyKeys: vi.fn().mockResolvedValue({}),
    } as unknown as KeyManager,
    getToken: () => 'test-bearer-token',
    timeoutConfig: {
      requestTimeout: 60000,
      uploadTimeout: 120000,
      downloadTimeout: 30000,
      maxSockets: 50,
      keepAlive: true,
    },
    retryConfig: {
      maxRetries: 0,
      baseDelay: 1000,
      maxDelay: 30000,
      enableLogging: false,
    },
    logger: { log: vi.fn() },
    maxBatchSize: 100,
    ...overrides,
  };
}

function setupMockRequest(statusCode: number, data: unknown): void {
  mockRequestFn.mockImplementation((_options: unknown, callback: (res: unknown) => void) => {
    const responseData = typeof data === 'string' ? data : JSON.stringify(data);
    const mockResponse = {
      statusCode,
      on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
        if (event === 'data') setImmediate(() => handler(Buffer.from(responseData)));
        if (event === 'end') setImmediate(() => handler());
        return mockResponse;
      }),
    };
    const mockReq = {
      on: vi.fn().mockReturnThis(),
      write: vi.fn(),
      end: vi.fn(),
      destroy: vi.fn(),
    };
    if (callback) setImmediate(() => callback(mockResponse));
    return mockReq as unknown as ClientRequest;
  });
}

describe('Golden: Send', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should throw when no capsas provided (empty array)', async () => {
    const service = new UploadService(createDefaultOptions());

    await expect(service.sendCapsas([], 'creator_1')).rejects.toThrow('No capsas provided');
  });

  it('should throw when more than 500 capsas provided', async () => {
    const service = new UploadService(createDefaultOptions());
    const builders = Array(501).fill(null).map(() => createMockBuilder());

    await expect(service.sendCapsas(builders, 'creator_1')).rejects.toThrow('limited to 500');
  });

  it('should send single capsa successfully', async () => {
    const result: SendResult = {
      batchId: 'batch_1',
      successful: 1,
      failed: 0,
      created: [{ packageId: 'pkg_1', index: 0 }],
    };
    setupMockRequest(200, result);

    const service = new UploadService(createDefaultOptions());
    const promise = service.sendCapsas([createMockBuilder()], 'creator_1');
    await vi.runAllTimersAsync();
    const res = await promise;

    expect(res.successful).toBe(1);
    expect(res.failed).toBe(0);
    expect(res.created).toHaveLength(1);
  });

  it('should include Bearer token in request headers', async () => {
    const result: SendResult = {
      batchId: 'b',
      successful: 1,
      failed: 0,
      created: [{ packageId: 'p', index: 0 }],
    };
    setupMockRequest(200, result);

    const service = new UploadService(createDefaultOptions());
    const promise = service.sendCapsas([createMockBuilder()], 'creator_1');
    await vi.runAllTimersAsync();
    await promise;

    const requestOptions = mockRequestFn.mock.calls[0]?.[0] as { headers?: Record<string, string> };
    expect(requestOptions?.headers?.Authorization).toBe('Bearer test-bearer-token');
  });

  it('should parse 207 multi-status with partial success', async () => {
    const result: SendResult = {
      batchId: 'batch_partial',
      successful: 2,
      failed: 1,
      partialSuccess: true,
      created: [
        { packageId: 'pkg_1', index: 0 },
        { packageId: 'pkg_2', index: 1 },
      ],
      errors: [{ index: 2, packageId: 'pkg_3', error: 'Validation failed' }],
    };
    setupMockRequest(207, result);

    const service = new UploadService(createDefaultOptions());
    const builders = [createMockBuilder(), createMockBuilder(), createMockBuilder()];
    const promise = service.sendCapsas(builders, 'creator_1');
    await vi.runAllTimersAsync();
    const res = await promise;

    expect(res.successful).toBe(2);
    expect(res.failed).toBe(1);
    expect(res.partialSuccess).toBe(true);
    expect(res.errors).toHaveLength(1);
  });

  it('should auto-split into batches by capsa count limit', async () => {
    let callCount = 0;
    mockRequestFn.mockImplementation((_options: unknown, callback: (res: unknown) => void) => {
      callCount++;
      const batchResult: SendResult = {
        batchId: `batch_${callCount}`,
        successful: 3,
        failed: 0,
        created: Array(3).fill(null).map((_, i) => ({
          packageId: `pkg_${callCount}_${i}`,
          index: i,
        })),
      };
      const mockResponse = {
        statusCode: 200,
        on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
          if (event === 'data') setImmediate(() => handler(Buffer.from(JSON.stringify(batchResult))));
          if (event === 'end') setImmediate(() => handler());
          return mockResponse;
        }),
      };
      const mockReq = {
        on: vi.fn().mockReturnThis(),
        write: vi.fn(),
        end: vi.fn(),
        destroy: vi.fn(),
      };
      if (callback) setImmediate(() => callback(mockResponse));
      return mockReq as unknown as ClientRequest;
    });

    const options = createDefaultOptions({ maxBatchSize: 3 });
    const service = new UploadService(options);
    const builders = Array(6).fill(null).map(() => createMockBuilder());
    const promise = service.sendCapsas(builders, 'creator_1');
    await vi.runAllTimersAsync();
    const res = await promise;

    expect(res.successful).toBe(6);
    expect(callCount).toBe(2);
  });

  it('should auto-split into batches by file count limit (500 files)', async () => {
    let callCount = 0;
    mockRequestFn.mockImplementation((_options: unknown, callback: (res: unknown) => void) => {
      callCount++;
      const batchResult: SendResult = {
        batchId: `batch_${callCount}`,
        successful: 1,
        failed: 0,
        created: [{ packageId: `pkg_${callCount}`, index: 0 }],
      };
      const mockResponse = {
        statusCode: 200,
        on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
          if (event === 'data') setImmediate(() => handler(Buffer.from(JSON.stringify(batchResult))));
          if (event === 'end') setImmediate(() => handler());
          return mockResponse;
        }),
      };
      const mockReq = {
        on: vi.fn().mockReturnThis(),
        write: vi.fn(),
        end: vi.fn(),
        destroy: vi.fn(),
      };
      if (callback) setImmediate(() => callback(mockResponse));
      return mockReq as unknown as ClientRequest;
    });

    const options = createDefaultOptions({ maxBatchSize: 1000 });
    const service = new UploadService(options);
    // Two capsas with 300 files each, exceeds 500-file batch limit
    const builders = [createMockBuilder(300), createMockBuilder(300)];
    const promise = service.sendCapsas(builders, 'creator_1');
    await vi.runAllTimersAsync();
    const res = await promise;

    expect(res.successful).toBe(2);
    expect(callCount).toBe(2); // Split into 2 batches
  });

  it('should aggregate results across multiple batches with adjusted indices', async () => {
    let callCount = 0;
    mockRequestFn.mockImplementation((_options: unknown, callback: (res: unknown) => void) => {
      callCount++;
      const batchResult: SendResult = {
        batchId: `batch_${callCount}`,
        successful: 2,
        failed: 0,
        created: [
          { packageId: `pkg_${callCount}_0`, index: 0 },
          { packageId: `pkg_${callCount}_1`, index: 1 },
        ],
      };
      const mockResponse = {
        statusCode: 200,
        on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
          if (event === 'data') setImmediate(() => handler(Buffer.from(JSON.stringify(batchResult))));
          if (event === 'end') setImmediate(() => handler());
          return mockResponse;
        }),
      };
      const mockReq = {
        on: vi.fn().mockReturnThis(),
        write: vi.fn(),
        end: vi.fn(),
        destroy: vi.fn(),
      };
      if (callback) setImmediate(() => callback(mockResponse));
      return mockReq as unknown as ClientRequest;
    });

    const options = createDefaultOptions({ maxBatchSize: 2 });
    const service = new UploadService(options);
    const builders = Array(4).fill(null).map(() => createMockBuilder());
    const promise = service.sendCapsas(builders, 'creator_1');
    await vi.runAllTimersAsync();
    const res = await promise;

    expect(res.successful).toBe(4);
    const indices = res.created.map(c => c.index);
    // First batch: 0,1; Second batch: 2,3
    expect(indices).toContain(0);
    expect(indices).toContain(1);
    expect(indices).toContain(2);
    expect(indices).toContain(3);
  });

  it('should use multipart/form-data content type', async () => {
    const result: SendResult = {
      batchId: 'b',
      successful: 1,
      failed: 0,
      created: [{ packageId: 'p', index: 0 }],
    };
    setupMockRequest(200, result);

    const service = new UploadService(createDefaultOptions());
    const promise = service.sendCapsas([createMockBuilder()], 'creator_1');
    await vi.runAllTimersAsync();
    await promise;

    const requestOptions = mockRequestFn.mock.calls[0]?.[0] as { headers?: Record<string, string> };
    expect(requestOptions?.headers?.['Content-Type']).toContain('multipart/form-data');
  });
});
