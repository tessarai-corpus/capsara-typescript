/**
 * Connect timeout on the SDK's HTTP agents, exercised against real local sockets.
 * @file tests/unit/internal/config/connect-timeout.test.ts
 */

import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import axios from 'axios';
import {
  DEFAULT_TIMEOUT_CONFIG,
  createAxiosConfig,
  createAgentForProtocol,
  createHttpAgent,
  createHttpsAgent,
  type HttpTimeoutConfig,
} from '../../../../src/internal/config/http-client.js';
import { createHttpClient } from '../../../../src/internal/http-factory.js';
import { parseApiError } from '../../../../src/errors/capsara-error.js';

vi.mock('../../../../src/internal/upload/multipart-builder.js', () => ({
  CapsasMultipartBuilder: vi.fn().mockImplementation(function () {
    return {
      addMetadata: vi.fn().mockReturnThis(),
      addCapsaMetadata: vi.fn().mockReturnThis(),
      addFileBinary: vi.fn().mockReturnThis(),
      build: vi.fn().mockReturnValue(Buffer.from('body')),
      getContentType: vi.fn().mockReturnValue('multipart/form-data; boundary=x'),
    };
  }),
}));

import { UploadService } from '../../../../src/internal/services/upload-service.js';
import type { CapsaBuilder } from '../../../../src/builder/capsa-builder.js';
import type { KeyManager } from '../../../../src/internal/services/key-service.js';

const CONNECT_MS = 150;
const config: HttpTimeoutConfig = { ...DEFAULT_TIMEOUT_CONFIG, connectTimeout: CONNECT_MS };

// Accepts TCP but never answers the TLS handshake, so 'secureConnect' never fires.
let stalledTls: net.Server;
let stalledPort = 0;
const stalledSockets = new Set<net.Socket>();

// Answers plain HTTP after a delay longer than the connect timeout.
let slowHttp: http.Server;
let slowPort = 0;

function listen(server: net.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve((server.address() as net.AddressInfo).port));
  });
}

function requestError(options: http.RequestOptions, lib: typeof http = http): Promise<NodeJS.ErrnoException> {
  return new Promise((resolve, reject) => {
    const req = lib.request(options, () => reject(new Error('unexpected response')));
    req.on('error', resolve);
    req.end();
  });
}

beforeAll(async () => {
  stalledTls = net.createServer((socket) => {
    stalledSockets.add(socket);
    socket.on('close', () => stalledSockets.delete(socket));
  });
  stalledPort = await listen(stalledTls);

  slowHttp = http.createServer((_req, res) => {
    setTimeout(() => res.end('{"ok":true}'), CONNECT_MS * 3);
  });
  slowPort = await listen(slowHttp);
});

afterAll(async () => {
  stalledSockets.forEach((s) => s.destroy());
  slowHttp.closeAllConnections();
  await Promise.all([
    new Promise((r) => stalledTls.close(r)),
    new Promise((r) => slowHttp.close(r)),
  ]);
});

describe('connect timeout', () => {
  it('destroys an HTTPS connection whose TLS handshake does not finish in time', async () => {
    const started = Date.now();
    const error = await requestError(
      { host: '127.0.0.1', port: stalledPort, agent: createHttpsAgent(config) },
      https as unknown as typeof http
    );

    expect(error.code).toBe('ETIMEDOUT');
    expect(error.message).toContain(`${CONNECT_MS} ms`);
    expect(Date.now() - started).toBeLessThan(CONNECT_MS * 20);
  });

  it('destroys an HTTP connection that does not connect in time', async () => {
    const error = await requestError({
      host: 'example.invalid',
      port: 80,
      agent: createHttpAgent(config),
      lookup: () => undefined,
    } as http.RequestOptions);

    expect(error.code).toBe('ETIMEDOUT');
  });

  it('applies the connect timeout to upload agents', async () => {
    const error = await requestError({
      host: 'example.invalid',
      port: 80,
      agent: createAgentForProtocol('http:', config.uploadTimeout, config),
      lookup: () => undefined,
    } as http.RequestOptions);

    expect(error.code).toBe('ETIMEDOUT');
  });

  it('does not limit a request once the socket has connected', async () => {
    const client = axios.create(createAxiosConfig(`http://127.0.0.1:${slowPort}`, 10_000, config));

    const response = await client.get('/');

    expect(response.data).toEqual({ ok: true });
  });

  it.each([0, Number.MAX_SAFE_INTEGER])('does not arm a timer when connectTimeout is %s', async (connectTimeout) => {
    const agent = createHttpAgent({ ...config, connectTimeout });
    const req = http.request({ host: 'example.invalid', port: 80, agent, lookup: () => undefined } as http.RequestOptions);
    const onError = vi.fn();
    req.on('error', onError);
    req.end();

    await new Promise((r) => setTimeout(r, CONNECT_MS * 2));
    expect(onError).not.toHaveBeenCalled();
    req.destroy();
  });

  it('surfaces as NETWORK_ERROR on API calls', async () => {
    const client = axios.create(createAxiosConfig(`https://127.0.0.1:${stalledPort}`, 10_000, config));

    const error = await client.get('/api/limits').catch((e: unknown) => e);

    expect(parseApiError(error, 'UNKNOWN').code).toBe('NETWORK_ERROR');
  });

  it('surfaces as NETWORK_ERROR on calls made through the HTTP client factory', async () => {
    const client = createHttpClient({ baseUrl: `https://127.0.0.1:${stalledPort}`, timeout: config, retry: { maxRetries: 0 } });

    const error = await client.get('/api/auth/me').catch((e: unknown) => e);

    expect(parseApiError(error, 'UNKNOWN').code).toBe('NETWORK_ERROR');
  });

  it('surfaces as NETWORK_ERROR on each capsa of an upload', async () => {
    const builder = {
      getFileCount: () => 1,
      getRecipientIds: () => ['recipient_1'],
      build: vi.fn().mockResolvedValue({
        capsa: { packageId: 'capsa_1' },
        files: [{ data: Buffer.from('x'), metadata: { fileId: 'file_0.enc' } }],
      }),
    } as unknown as CapsaBuilder;
    const service = new UploadService({
      baseUrl: `https://127.0.0.1:${stalledPort}`,
      keyManager: { fetchPartyKeys: vi.fn().mockResolvedValue([]) } as unknown as KeyManager,
      getToken: () => 'token',
      timeoutConfig: config,
      retryConfig: { maxRetries: 0, baseDelay: 1, maxDelay: 1, enableLogging: false, logger: { log: vi.fn() } },
      logger: { log: vi.fn() },
      maxBatchSize: 100,
      getLimits: async () => ({ maxFileSize: 1024, maxFilesPerCapsa: 10, maxTotalSize: 1024 }),
    });

    const result = await service.sendCapsas([builder], 'creator_1');

    expect(result.failed).toBe(1);
    expect(result.errors?.[0]).toMatchObject({ index: 0, code: 'NETWORK_ERROR' });
  });
});
