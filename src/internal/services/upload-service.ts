/** Capsa upload service with batching and retry logic. */

import * as http from 'http';
import * as https from 'https';
import { CapsasMultipartBuilder } from '../upload/multipart-builder.js';
import { createAgentForProtocol, type HttpTimeoutConfig } from '../config/http-client.js';
import type { RetryConfig, RetryLogger } from '../config/retry-interceptor.js';
import type { CapsaBuilder } from '../../builder/capsa-builder.js';
import type { KeyManager } from './key-service.js';
import { SDK_VERSION, buildUserAgent } from '../version.js';

export interface UploadServiceOptions {
  baseUrl: string;
  keyManager: KeyManager;
  getToken: () => string | null;
  timeoutConfig: HttpTimeoutConfig;
  retryConfig: Required<RetryConfig>;
  logger: RetryLogger;
  maxBatchSize: number;
  userAgent?: string;
}

export interface SendResult {
  batchId: string;
  successful: number;
  failed: number;
  partialSuccess?: boolean;
  created: Array<{ packageId: string; index: number }>;
  errors?: Array<{ index: number; packageId: string; error: string }>;
}

export class UploadService {
  private baseUrl: string;
  private keyManager: KeyManager;
  private getToken: () => string | null;
  private timeoutConfig: HttpTimeoutConfig;
  private retryConfig: Required<RetryConfig>;
  private logger: RetryLogger;
  private maxBatchSize: number;
  private userAgent: string;

  constructor(options: UploadServiceOptions) {
    this.baseUrl = options.baseUrl;
    this.keyManager = options.keyManager;
    this.getToken = options.getToken;
    this.timeoutConfig = options.timeoutConfig;
    this.retryConfig = options.retryConfig;
    this.logger = options.logger;
    this.maxBatchSize = options.maxBatchSize;
    this.userAgent = buildUserAgent(options.userAgent);
  }

  /**
   * Send capsas with automatic batch splitting
   * @param builders - Array of CapsaBuilder instances
   * @param creatorId - Creator party ID
   * @returns Send result
   */
  async sendCapsas(builders: CapsaBuilder[], creatorId: string): Promise<SendResult> {
    if (builders.length === 0) {
      throw new Error('No capsas provided to send');
    }

    if (builders.length > 500) {
      throw new Error('Send limited to 500 capsas per request');
    }

    // Validate no single capsa exceeds file limit
    const MAX_FILES_PER_BATCH = 500;
    for (let i = 0; i < builders.length; i++) {
      const fileCount = builders[i]!.getFileCount();
      if (fileCount > MAX_FILES_PER_BATCH) {
        throw new Error(
          `Capsa at index ${i} has ${fileCount} files, exceeding the batch limit of ${MAX_FILES_PER_BATCH} files.`
        );
      }
    }

    return this.sendInBalancedBatches(builders, creatorId);
  }

  /**
   * Send capsas in balanced batches
   */
  private async sendInBalancedBatches(builders: CapsaBuilder[], creatorId: string): Promise<SendResult> {
    const MAX_FILES_PER_BATCH = 500;
    const totalFiles = builders.reduce((sum, builder) => sum + builder.getFileCount(), 0);

    const chunks: CapsaBuilder[][] = [];
    let currentChunk: CapsaBuilder[] = [];
    let currentChunkFileCount = 0;

    for (const builder of builders) {
      const builderFileCount = builder.getFileCount();
      const wouldExceedCapsaLimit = currentChunk.length >= this.maxBatchSize;
      const wouldExceedFileLimit = currentChunkFileCount + builderFileCount > MAX_FILES_PER_BATCH;

      if (currentChunk.length > 0 && (wouldExceedCapsaLimit || wouldExceedFileLimit)) {
        chunks.push(currentChunk);
        currentChunk = [builder];
        currentChunkFileCount = builderFileCount;
      } else {
        currentChunk.push(builder);
        currentChunkFileCount += builderFileCount;
      }
    }

    if (currentChunk.length > 0) {
      chunks.push(currentChunk);
    }

    if (this.retryConfig.enableLogging) {
      const chunkSummary = chunks.map(chunk => {
        const capsaCount = chunk.length;
        const fileCount = chunk.reduce((sum, b) => sum + b.getFileCount(), 0);
        return `${capsaCount}capsa/${fileCount}files`;
      }).join(', ');

      this.logger.log(
        `[Capsara SDK] Smart auto-split: ${builders.length} capsas (${totalFiles} files) → ` +
        `${chunks.length} batches (${chunkSummary})`
      );
    }

    const results: SendResult[] = [];
    let currentOffset = 0;

    for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex++) {
      const chunk = chunks[chunkIndex]!;

      if (this.retryConfig.enableLogging) {
        this.logger.log(
          `[Capsara SDK] Sending batch ${chunkIndex + 1}/${chunks.length} ` +
          `(${chunk.length} capsas, offset: ${currentOffset})`
        );
      }

      try {
        const allPartyIds = new Set<string>([creatorId]);
        chunk.forEach(builder => {
          builder.getRecipientIds().forEach(id => allPartyIds.add(id));
        });

        const partyKeys = await this.keyManager.fetchPartyKeys(Array.from(allPartyIds));

        const builtCapsas = await Promise.all(
          chunk.map(builder => builder.build(partyKeys))
        );

        const multipartBuilder = new CapsasMultipartBuilder();
        multipartBuilder.addMetadata(chunk.length, creatorId);

        builtCapsas.forEach((builtCapsa, capsaIndex) => {
          multipartBuilder.addCapsaMetadata(builtCapsa.capsa, capsaIndex);

          builtCapsa.files.forEach((file) => {
            multipartBuilder.addFileBinary(file.data, file.metadata.fileId);
          });
        });

        const body = multipartBuilder.build();
        const result = await this.sendWithRetry(body, multipartBuilder.getContentType());

        const adjustedResult: SendResult = {
          ...result,
          created: result.created.map(item => ({
            ...item,
            index: item.index + currentOffset,
          })),
          errors: result.errors?.map(item => ({
            ...item,
            index: item.index + currentOffset,
          })),
        };

        results.push(adjustedResult);
        currentOffset += chunk.length;

        if (this.retryConfig.enableLogging) {
          this.logger.log(
            `[Capsara SDK] Batch ${chunkIndex + 1}/${chunks.length} completed: ` +
            `${result.successful} succeeded, ${result.failed} failed`
          );
        }
      } catch (error) {
        const failedErrors = chunk.map((_, index) => ({
          index: currentOffset + index,
          packageId: '',
          error: error instanceof Error ? error.message : 'Unknown error',
        }));

        results.push({
          batchId: '',
          successful: 0,
          failed: chunk.length,
          partialSuccess: false,
          created: [],
          errors: failedErrors,
        });

        currentOffset += chunk.length;

        if (this.retryConfig.enableLogging) {
          this.logger.log(
            `[Capsara SDK] Batch ${chunkIndex + 1}/${chunks.length} failed: ` +
            `${error instanceof Error ? error.message : 'Unknown error'}`
          );
        }
      }
    }

    const allErrors = results.flatMap(r => r.errors || []);
    const aggregated: SendResult = {
      batchId: results[0]?.batchId || `batch_${Date.now()}`,
      successful: results.reduce((sum, r) => sum + r.successful, 0),
      failed: results.reduce((sum, r) => sum + r.failed, 0),
      partialSuccess: results.some(r => r.partialSuccess) ||
                      (results.some(r => r.successful > 0) && results.some(r => r.failed > 0)),
      created: results.flatMap(r => r.created),
    };

    if (allErrors.length > 0) {
      aggregated.errors = allErrors;
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

  /**
   * Send multipart request with retry logic
   */
  private async sendWithRetry(
    body: Buffer,
    contentType: string,
    retryCount: number = 0
  ): Promise<SendResult> {
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
          if (res.statusCode && ((res.statusCode >= 200 && res.statusCode < 300) || res.statusCode === 207)) {
            try {
              const response = JSON.parse(responseData) as SendResult;
              resolve(response);
            } catch (error) {
              reject(new Error(`Failed to parse response: ${error instanceof Error ? error.message : 'Unknown'}`));
            }
          } else {
            const isRetryable = res.statusCode === 503 || res.statusCode === 429;
            if (isRetryable && retryCount < this.retryConfig.maxRetries) {
              const retryDelay = this.calculateRetryDelay(responseData, retryCount, res.statusCode);

              if (this.retryConfig.enableLogging) {
                this.logger.log(
                  `[Capsara SDK] Retry attempt ${retryCount + 1}/${this.retryConfig.maxRetries} ` +
                  `for ${res.statusCode} error - waiting ${Math.floor(retryDelay)}ms`
                );
              }

              globalThis.setTimeout(() => {
                this.sendWithRetry(body, contentType, retryCount + 1)
                  .then(resolve)
                  .catch(reject);
              }, retryDelay);
            } else {
              reject(new Error(`Send failed with status ${res.statusCode}: ${responseData}`));
            }
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Upload timeout after ${this.timeoutConfig.uploadTimeout / 1000} seconds`));
      });

      // Write body in chunks
      const chunkSize = 64 * 1024;
      for (let i = 0; i < body.length; i += chunkSize) {
        req.write(body.subarray(i, Math.min(i + chunkSize, body.length)));
      }
      req.end();
    });
  }

  /**
   * Calculate retry delay
   */
  private calculateRetryDelay(responseData: string, retryCount: number, _statusCode: number | undefined): number {
    try {
      const errorResponse = JSON.parse(responseData) as { error?: { retryAfter?: number } };
      const serverDelay = errorResponse?.error?.retryAfter;
      if (typeof serverDelay === 'number') {
        return Math.min(serverDelay * 1000, this.retryConfig.maxDelay);
      }
    } catch {
      // Parse failed, use exponential backoff
    }

    const exponentialDelay = this.retryConfig.baseDelay * Math.pow(2, retryCount);
    const jitter = Math.random() * 0.3 * exponentialDelay;
    return Math.min(exponentialDelay + jitter, this.retryConfig.maxDelay);
  }
}
