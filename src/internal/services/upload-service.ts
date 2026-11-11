/** Capsa upload service with batching and retry logic. */

import * as http from 'http';
import * as https from 'https';
import { CapsasMultipartBuilder } from '../upload/multipart-builder.js';
import { createAgentForProtocol, type HttpTimeoutConfig } from '../config/http-client.js';
import {
  classifyFailure,
  computeRetryDelay,
  getServerSuggestedDelay,
  isRetryableFailure,
  isRetryableStatus,
  sleep,
  type RetryConfig,
  type RetryLogger,
} from '../config/retry-interceptor.js';
import type { TokenRefresher } from '../config/token-refresh.js';
import type { BuiltCapsa, CapsaBuilder } from '../../builder/capsa-builder.js';
import type { KeyManager } from './key-service.js';
import type { PartyKey, SystemLimits } from '../../types/index.js';
import { SDK_VERSION, buildUserAgent } from '../version.js';
import { CapsaraError, parseErrorResponse } from '../../errors/capsara-error.js';

const STALE_PARTY_GRAPH_CODES = ['KEYCHAIN_DELEGATES_MISMATCH', 'KEYCHAIN_KEY_OUTDATED'];

const MAX_KEYCHAIN_REBUILDS = 1;

const FALLBACK_MAX_REQUEST_SIZE = 2 * 1024 * 1024 * 1024;

const FALLBACK_MAX_REQUEST_FIELD_BYTES = 64 * 1024 * 1024;

const FALLBACK_MAX_FILES_PER_REQUEST = 500;

interface RequestLimits {
  maxRequestSize: number;
  maxRequestFieldBytes: number;
  maxFilesPerRequest: number;
}

function positiveOr(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : fallback;
}

interface PendingCapsa {
  builder: CapsaBuilder;
  position: number;
}

interface BuiltPair extends PendingCapsa {
  built: BuiltCapsa;
}

export interface UploadServiceOptions {
  baseUrl: string;
  keyManager: KeyManager;
  getToken: () => string | null;
  tokenRefresher?: TokenRefresher;
  timeoutConfig: HttpTimeoutConfig;
  retryConfig: Required<RetryConfig>;
  logger: RetryLogger;
  maxBatchSize: number;
  getLimits: () => Promise<SystemLimits>;
  userAgent?: string;
}

export interface SendCreated {
  index: number;
  packageId: string;
  createdAt: string;
}

export interface SendFailure {
  index: number;
  packageId?: string;
  code: string;
  error: string;
}

export interface SendResult {
  batchId: string;
  successful: number;
  failed: number;
  partialSuccess?: boolean;
  created: SendCreated[];
  errors?: SendFailure[];
}

interface SendResponseBody {
  success?: boolean;
  batchId?: string;
  successful?: number;
  failed?: number;
  created?: Array<{ index: number; packageId: string; createdAt: string }>;
  errors?: Array<{ index: number; packageId?: string; code?: string; message?: string }>;
}

interface GroupOutcome {
  batchId?: string;
  created: SendCreated[];
  errors: SendFailure[];
}

function toFailure(position: number, error: unknown, fallbackCode: string, packageId?: string): SendFailure {
  return {
    index: position,
    ...(packageId && { packageId }),
    code: error instanceof CapsaraError ? error.code : fallbackCode,
    error: error instanceof Error ? error.message : String(error),
  };
}

function validationError(message: string, details?: { index: number }): CapsaraError {
  return new CapsaraError(message, 'VALIDATION_ERROR', 0, details);
}

function invalidResponse(pair: BuiltPair, message: string): SendFailure {
  return { index: pair.position, packageId: pair.built.capsa.packageId, code: 'INVALID_RESPONSE', error: message };
}

function isSendResponseBody(value: unknown): value is SendResponseBody {
  if (typeof value !== 'object' || value === null) return false;
  const body = value as SendResponseBody;
  return Array.isArray(body.created) || Array.isArray(body.errors);
}

export class UploadService {
  private baseUrl: string;
  private keyManager: KeyManager;
  private getToken: () => string | null;
  private tokenRefresher: TokenRefresher | undefined;
  private timeoutConfig: HttpTimeoutConfig;
  private retryConfig: Required<RetryConfig>;
  private logger: RetryLogger;
  private maxBatchSize: number;
  private getLimits: () => Promise<SystemLimits>;
  private userAgent: string;

  constructor(options: UploadServiceOptions) {
    this.baseUrl = options.baseUrl;
    this.keyManager = options.keyManager;
    this.getToken = options.getToken;
    this.tokenRefresher = options.tokenRefresher;
    this.timeoutConfig = options.timeoutConfig;
    this.retryConfig = options.retryConfig;
    this.logger = options.logger;
    this.maxBatchSize = options.maxBatchSize;
    this.getLimits = options.getLimits;
    this.userAgent = buildUserAgent(options.userAgent);
  }

  async sendCapsas(builders: CapsaBuilder[], creatorId: string): Promise<SendResult> {
    if (builders.length === 0) {
      throw validationError('No capsas provided to send');
    }

    if (builders.length > 500) {
      throw validationError('Send limited to 500 capsas per request');
    }

    const limits = await this.resolveRequestLimits();

    for (let i = 0; i < builders.length; i++) {
      if (builders[i]!.getRecipientIds().length === 0) {
        throw validationError(
          `Capsa at index ${i} has no recipient. Call addRecipient() with the party this capsa is sent to.`,
          { index: i }
        );
      }
      const fileCount = builders[i]!.getFileCount();
      if (fileCount > limits.maxFilesPerRequest) {
        throw validationError(
          `Capsa at index ${i} has ${fileCount} files, exceeding the batch limit of ${limits.maxFilesPerRequest} files.`,
          { index: i }
        );
      }
    }

    return this.sendInBalancedBatches(builders, creatorId, limits);
  }

  private chunkBuilders(builders: CapsaBuilder[], maxFilesPerRequest: number): PendingCapsa[][] {
    const chunks: PendingCapsa[][] = [];
    let currentChunk: PendingCapsa[] = [];
    let currentChunkFileCount = 0;

    builders.forEach((builder, position) => {
      const builderFileCount = builder.getFileCount();
      const wouldExceedCapsaLimit = currentChunk.length >= this.maxBatchSize;
      const wouldExceedFileLimit = currentChunkFileCount + builderFileCount > maxFilesPerRequest;

      if (currentChunk.length > 0 && (wouldExceedCapsaLimit || wouldExceedFileLimit)) {
        chunks.push(currentChunk);
        currentChunk = [];
        currentChunkFileCount = 0;
      }

      currentChunk.push({ builder, position });
      currentChunkFileCount += builderFileCount;
    });

    if (currentChunk.length > 0) {
      chunks.push(currentChunk);
    }

    return chunks;
  }

  private async sendInBalancedBatches(
    builders: CapsaBuilder[],
    creatorId: string,
    limits: RequestLimits
  ): Promise<SendResult> {
    const chunks = this.chunkBuilders(builders, limits.maxFilesPerRequest);

    if (this.retryConfig.enableLogging) {
      const totalFiles = builders.reduce((sum, builder) => sum + builder.getFileCount(), 0);
      const chunkSummary = chunks.map(chunk => {
        const fileCount = chunk.reduce((sum, p) => sum + p.builder.getFileCount(), 0);
        return `${chunk.length}capsa/${fileCount}files`;
      }).join(', ');

      this.logger.log(
        `[Capsara SDK] Smart auto-split: ${builders.length} capsas (${totalFiles} files) → ` +
        `${chunks.length} batches (${chunkSummary})`
      );
    }

    const created: SendCreated[] = [];
    const errors: SendFailure[] = [];
    const batchIds: string[] = [];

    for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex++) {
      const chunk = chunks[chunkIndex]!;

      if (this.retryConfig.enableLogging) {
        this.logger.log(
          `[Capsara SDK] Sending batch ${chunkIndex + 1}/${chunks.length} ` +
          `(${chunk.length} capsas, offset: ${chunk[0]!.position})`
        );
      }

      const allPartyIds = new Set<string>([creatorId]);
      chunk.forEach(({ builder }) => {
        builder.getRecipientIds().forEach(id => allPartyIds.add(id));
      });
      const partyIds = Array.from(allPartyIds);

      let partyKeys: PartyKey[];
      try {
        partyKeys = await this.keyManager.fetchPartyKeys(partyIds);
      } catch (error) {
        chunk.forEach(p => errors.push(toFailure(p.position, error, 'UPLOAD_FAILED')));
        this.logBatchFailure(chunkIndex, chunks.length, error);
        continue;
      }

      const pairs = await this.buildAll(chunk, partyKeys, errors);
      if (pairs.length === 0) {
        continue;
      }

      const groups = this.splitByRequestSize(pairs, limits);

      if (this.retryConfig.enableLogging && groups.length > 1) {
        this.logger.log(
          `[Capsara SDK] Batch ${chunkIndex + 1} split into ${groups.length} requests ` +
          `to stay within the request size limit`
        );
      }

      for (const group of groups) {
        try {
          const outcome = await this.sendGroup(group, creatorId, partyIds, chunkIndex);
          created.push(...outcome.created);
          errors.push(...outcome.errors);
          if (outcome.batchId) {
            batchIds.push(outcome.batchId);
          }
        } catch (error) {
          group.forEach(p => errors.push(
            toFailure(p.position, error, 'UPLOAD_FAILED', p.built.capsa.packageId)
          ));
          this.logBatchFailure(chunkIndex, chunks.length, error);
        }
      }

      if (this.retryConfig.enableLogging) {
        this.logger.log(
          `[Capsara SDK] Batch ${chunkIndex + 1}/${chunks.length} completed`
        );
      }
    }

    created.sort((a, b) => a.index - b.index);
    errors.sort((a, b) => a.index - b.index);

    const aggregated: SendResult = {
      batchId: batchIds[0] || `batch_${Date.now()}`,
      successful: created.length,
      failed: errors.length,
      partialSuccess: created.length > 0 && errors.length > 0,
      created,
    };

    if (errors.length > 0) {
      aggregated.errors = errors;
    }

    if (this.retryConfig.enableLogging) {
      this.logger.log(
        `[Capsara SDK] All batches completed: ` +
        `${aggregated.successful}/${builders.length} succeeded, ` +
        `${aggregated.failed}/${builders.length} failed`
      );
    }

    return aggregated;
  }

  private logBatchFailure(chunkIndex: number, chunkCount: number, error: unknown): void {
    if (this.retryConfig.enableLogging) {
      this.logger.log(
        `[Capsara SDK] Batch ${chunkIndex + 1}/${chunkCount} failed: ` +
        `${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async buildAll(
    pending: PendingCapsa[],
    partyKeys: PartyKey[],
    errors: SendFailure[]
  ): Promise<BuiltPair[]> {
    const settled = await Promise.allSettled(pending.map(p => p.builder.build(partyKeys)));
    const pairs: BuiltPair[] = [];

    settled.forEach((result, i) => {
      const { builder, position } = pending[i]!;
      if (result.status === 'fulfilled') {
        pairs.push({ builder, position, built: result.value });
      } else {
        errors.push(toFailure(position, result.reason, 'BUILD_FAILED'));
      }
    });

    return pairs;
  }

  private async sendWithRetry(
    body: Buffer,
    contentType: string,
    retryCount: number = 0,
    refreshed: boolean = false
  ): Promise<SendResponseBody> {
    return new Promise((resolve, reject) => {
      const url = new URL(`${this.baseUrl}/api/capsas`);
      const token = this.getToken();

      const agent = createAgentForProtocol(
        url.protocol,
        this.timeoutConfig.uploadTimeout,
        this.timeoutConfig
      );

      const options: http.RequestOptions = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': contentType,
          'Content-Length': body.length.toString(),
          Authorization: token ? `Bearer ${token}` : '',
          'User-Agent': this.userAgent,
          'X-SDK-Version': SDK_VERSION,
        },
        timeout: this.timeoutConfig.uploadTimeout,
        agent,
      };

      const requester = url.protocol === 'https:' ? https : http;
      const req = requester.request(options, (res) => {
        let responseData = '';

        res.on('data', (chunk: Buffer) => {
          responseData += chunk.toString('utf-8');
        });

        res.on('end', () => {
          const status = res.statusCode ?? 0;

          if (status >= 200 && status < 300) {
            let parsed: unknown;
            try {
              parsed = JSON.parse(responseData);
            } catch (error) {
              reject(new CapsaraError(
                `Failed to parse send response: ${error instanceof Error ? error.message : 'Unknown'}`,
                'INVALID_RESPONSE',
                status
              ));
              return;
            }
            if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
              reject(new CapsaraError('Send response body is not a JSON object', 'INVALID_RESPONSE', status));
              return;
            }
            resolve(parsed);
            return;
          }

          if (status === 401 && !refreshed && this.tokenRefresher?.canRefresh()) {
            this.retryAfterRefresh(
              body,
              contentType,
              retryCount,
              this.toUploadError(status, res.statusMessage, res.headers, responseData)
            )
              .then(resolve)
              .catch(reject);
            return;
          }

          if (status === 422) {
            const parsed = this.tryParseJson(responseData);
            if (isSendResponseBody(parsed)) {
              resolve(parsed);
              return;
            }
          }

          if (isRetryableStatus(status) && retryCount < this.retryConfig.maxRetries) {
            this.scheduleRetry(
              body, contentType, retryCount, refreshed, String(status),
              getServerSuggestedDelay(responseData, res.headers)
            ).then(resolve, reject);
            return;
          }

          reject(this.toUploadError(status, res.statusMessage, res.headers, responseData));
        });
      });

      let timedOut = false;
      req.on('error', (error: Error & { code?: string }) => {
        if (timedOut) return;
        if (isRetryableFailure(classifyFailure(error), 'post') && retryCount < this.retryConfig.maxRetries) {
          this.scheduleRetry(body, contentType, retryCount, refreshed, error.code ?? 'network error', null)
            .then(resolve, reject);
          return;
        }
        reject(new CapsaraError(`Network error during upload: ${error.message}`, 'NETWORK_ERROR', 0, {
          originalError: error.message,
        }));
      });
      req.on('timeout', () => {
        timedOut = true;
        req.destroy();
        reject(new CapsaraError(
          `Upload timeout after ${this.timeoutConfig.uploadTimeout / 1000} seconds`,
          'UPLOAD_TIMEOUT',
          0
        ));
      });

      const chunkSize = 64 * 1024;
      for (let i = 0; i < body.length; i += chunkSize) {
        req.write(body.subarray(i, Math.min(i + chunkSize, body.length)));
      }
      req.end();
    });
  }

  private async retryAfterRefresh(
    body: Buffer,
    contentType: string,
    retryCount: number,
    unauthorized: CapsaraError
  ): Promise<SendResponseBody> {
    const refresher = this.tokenRefresher!;
    if (await refresher.refresh()) {
      return this.sendWithRetry(body, contentType, retryCount, true);
    }
    throw refresher.getLastRefreshError() ?? unauthorized;
  }

  private tryParseJson(text: string): unknown {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return undefined;
    }
  }

  private encryptedSize(built: BuiltCapsa): number {
    return built.files.reduce((sum, file) => sum + file.data.length, 0);
  }

  private jsonFieldSize(built: BuiltCapsa): number {
    return Buffer.byteLength(JSON.stringify(built.capsa), 'utf-8');
  }

  private async resolveRequestLimits(): Promise<RequestLimits> {
    const limits = await this.getLimits();
    return {
      maxRequestSize: positiveOr(limits.maxRequestSize, FALLBACK_MAX_REQUEST_SIZE),
      maxRequestFieldBytes: positiveOr(limits.maxRequestFieldBytes, FALLBACK_MAX_REQUEST_FIELD_BYTES),
      maxFilesPerRequest: positiveOr(limits.maxFilesPerRequest, FALLBACK_MAX_FILES_PER_REQUEST),
    };
  }

  private splitByRequestSize(
    pairs: BuiltPair[],
    limits: RequestLimits
  ): BuiltPair[][] {
    const groups: BuiltPair[][] = [];
    let group: BuiltPair[] = [];
    let groupBytes = 0;
    let groupFieldBytes = 0;

    for (const pair of pairs) {
      const fieldBytes = this.jsonFieldSize(pair.built);
      const bytes = this.encryptedSize(pair.built) + fieldBytes;

      if (
        group.length > 0 &&
        (groupBytes + bytes > limits.maxRequestSize || groupFieldBytes + fieldBytes > limits.maxRequestFieldBytes)
      ) {
        groups.push(group);
        group = [];
        groupBytes = 0;
        groupFieldBytes = 0;
      }

      group.push(pair);
      groupBytes += bytes;
      groupFieldBytes += fieldBytes;
    }

    if (group.length > 0) {
      groups.push(group);
    }

    return groups;
  }

  private mapResponse(body: SendResponseBody, sent: BuiltPair[]): GroupOutcome {
    const createdItems = Array.isArray(body.created) ? body.created : [];
    const errorItems = Array.isArray(body.errors) ? body.errors : [];
    const answered = new Set<number>();
    const indexesValid = [...createdItems, ...errorItems].every(item => {
      const index: unknown = item?.index;
      if (typeof index !== 'number' || !Number.isInteger(index) || index < 0 || index >= sent.length || answered.has(index)) {
        return false;
      }
      answered.add(index);
      return true;
    });

    if (!indexesValid) {
      return {
        ...(body.batchId && { batchId: body.batchId }),
        created: [],
        errors: sent.map(pair => invalidResponse(pair, 'Send response has a missing, duplicate or out-of-range capsa index')),
      };
    }

    return {
      ...(body.batchId && { batchId: body.batchId }),
      created: createdItems.map(item => ({
        index: sent[item.index]!.position,
        packageId: item.packageId,
        createdAt: item.createdAt,
      })),
      errors: [
        ...errorItems.map(item => ({
          index: sent[item.index]!.position,
          ...(item.packageId && { packageId: item.packageId }),
          code: item.code ?? 'UNKNOWN_ERROR',
          error: item.message ?? 'Capsa was not created',
        })),
        ...sent
          .filter((_, index) => !answered.has(index))
          .map(pair => invalidResponse(pair, 'Send response did not report this capsa')),
      ],
    };
  }

  private async sendGroup(
    group: BuiltPair[],
    creatorId: string,
    partyIds: string[],
    chunkIndex: number
  ): Promise<GroupOutcome> {
    let current = group;
    const rebuildErrors: SendFailure[] = [];

    for (let attempt = 0; ; attempt++) {
      const multipartBuilder = new CapsasMultipartBuilder();
      multipartBuilder.addMetadata(current.length, creatorId);

      current.forEach(({ built }, capsaIndex) => {
        multipartBuilder.addCapsaMetadata(built.capsa, capsaIndex);
        built.files.forEach((file) => {
          multipartBuilder.addFileBinary(file.data, file.metadata.fileId);
        });
      });

      try {
        const body = await this.sendWithRetry(multipartBuilder.build(), multipartBuilder.getContentType());
        const outcome = this.mapResponse(body, current);
        return { ...outcome, errors: [...rebuildErrors, ...outcome.errors] };
      } catch (error) {
        const isStalePartyGraph =
          error instanceof CapsaraError && STALE_PARTY_GRAPH_CODES.includes(error.code);
        if (!isStalePartyGraph || attempt >= MAX_KEYCHAIN_REBUILDS) {
          throw error;
        }

        if (this.retryConfig.enableLogging) {
          this.logger.log(
            `[Capsara SDK] Recipient keys or delegates changed during upload — ` +
            `re-fetching party keys and rebuilding batch ${chunkIndex + 1}`
          );
        }

        const partyKeys = await this.keyManager.fetchPartyKeys(partyIds);
        current = await this.buildAll(current, partyKeys, rebuildErrors);
        if (current.length === 0) {
          return { created: [], errors: rebuildErrors };
        }
      }
    }
  }

  private toUploadError(
    status: number,
    statusText: string | undefined,
    headers: http.IncomingHttpHeaders,
    responseData: string
  ): CapsaraError {
    const parsed = parseErrorResponse({
      status,
      statusText,
      headers,
      data: responseData,
    });
    return new CapsaraError(parsed.message, parsed.code, parsed.statusCode, parsed.details, parsed.response, parsed);
  }

  private async scheduleRetry(
    body: Buffer,
    contentType: string,
    retryCount: number,
    refreshed: boolean,
    reason: string,
    serverDelay: number | null
  ): Promise<SendResponseBody> {
    const { delay, source } = computeRetryDelay(retryCount, serverDelay, this.retryConfig);

    if (this.retryConfig.enableLogging) {
      this.logger.log(
        `[Capsara SDK] Retry attempt ${retryCount + 1}/${this.retryConfig.maxRetries} ` +
        `for ${reason} error - waiting ${delay}ms (${source})`
      );
    }

    await sleep(delay);
    return this.sendWithRetry(body, contentType, retryCount + 1, refreshed);
  }
}
