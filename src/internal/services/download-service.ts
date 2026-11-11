/** File download and decryption service. */

import type { AxiosInstance } from 'axios';
import { decryptFilename } from '../decryptor/capsa-decryptor.js';
import { decryptAESRaw } from '../crypto/primitives.js';
import { decompressData } from '../crypto/compression.js';
import { sanitizeFilename } from '../utils/safe-filename.js';
import { CapsaraCapsaError } from '../../errors/capsa-error.js';
import type { AxiosLikeError } from '../../errors/capsara-error.js';
import {
  classifyFailure,
  computeRetryDelay,
  describeFailure,
  getServerSuggestedDelay,
  isRetryableFailure,
  sleep,
  type RetryConfig,
  type RetryLogger,
} from '../config/retry-interceptor.js';

export interface DownloadServiceOptions {
  axiosInstance: AxiosInstance;
  blobClient: AxiosInstance;
  retryConfig: Required<RetryConfig>;
  logger: RetryLogger;
}

export interface FileMetadata {
  iv: string;
  authTag: string;
  compressed?: boolean;
  encryptedFilename: string;
  filenameIV: string;
  filenameAuthTag: string;
}

export interface DecryptedFileResult {
  /** Decrypted file contents. */
  data: Buffer;
  /**
   * The file name exactly as the sender supplied it. It is untrusted and can
   * hold path separators or other unsafe characters; do not use it as a path.
   */
  filename: string;
  /**
   * The file name made safe to write to disk: a single path segment with no
   * separators, control characters, Windows-invalid characters or reserved
   * device names, at most 255 UTF-8 bytes. Join it to a directory you chose.
   * See sanitizeFilename for the rules.
   */
  readonly safeFilename: string;
}

export class DownloadService {
  private http: AxiosInstance;
  private blobDownloadClient: AxiosInstance;
  private retryConfig: Required<RetryConfig>;
  private logger: RetryLogger;

  constructor(options: DownloadServiceOptions) {
    this.http = options.axiosInstance;
    this.blobDownloadClient = options.blobClient;
    this.retryConfig = options.retryConfig;
    this.logger = options.logger;
  }

  async getFileDownloadUrl(
    capsaId: string,
    fileId: string,
    expiresInMinutes = 60
  ): Promise<{ downloadUrl: string; expiresAt: string }> {
    let data: unknown;
    try {
      const response = await this.http.get<unknown>(`/api/capsas/${capsaId}/files/${fileId}/download`, {
        params: { expires: expiresInMinutes },
      });
      data = response.data;
    } catch (error) {
      throw CapsaraCapsaError.fromApiError(error);
    }
    if (typeof data !== 'object' || data === null || Array.isArray(data)) {
      throw new CapsaraCapsaError(
        `The server returned an unexpected download response body for file ${fileId} in capsa ${capsaId}.`,
        'INVALID_RESPONSE',
        0,
        { capsaId, fileId }
      );
    }
    const { downloadUrl, expiresAt } = data as { downloadUrl: string; expiresAt: string };
    return { downloadUrl, expiresAt };
  }

  async downloadEncryptedFile(capsaId: string, fileId: string): Promise<Buffer> {
    const { downloadUrl } = await this.getFileDownloadUrl(capsaId, fileId);
    return this.downloadFileWithRetry(downloadUrl, 0);
  }

  async downloadAndDecryptFile(
    capsaId: string,
    fileId: string,
    masterKey: Buffer,
    metadata: FileMetadata
  ): Promise<DecryptedFileResult> {
    const { downloadUrl } = await this.getFileDownloadUrl(capsaId, fileId);
    try {
      const encryptedData = await this.downloadFileWithRetry(downloadUrl, 0);

      const ivBuffer = Buffer.from(metadata.iv, 'base64url');
      const authTagBuffer = Buffer.from(metadata.authTag, 'base64url');
      let decryptedData = decryptAESRaw(encryptedData, masterKey, ivBuffer, authTagBuffer);

      if (metadata.compressed) {
        decryptedData = await decompressData(decryptedData);
      }

      const filename = decryptFilename(
        metadata.encryptedFilename,
        masterKey,
        metadata.filenameIV,
        metadata.filenameAuthTag
      );

      return { data: decryptedData, filename, safeFilename: sanitizeFilename(filename) };
    } catch (error) {
      throw CapsaraCapsaError.downloadFailed(capsaId, fileId, error);
    }
  }

  private async downloadFileWithRetry(downloadUrl: string, retryCount: number): Promise<Buffer> {
    try {
      const response = await this.blobDownloadClient.get<ArrayBuffer>(downloadUrl, {
        responseType: 'arraybuffer',
      });

      return Buffer.from(response.data);
    } catch (error) {
      if (!isRetryableFailure(classifyFailure(error), 'get') || retryCount >= this.retryConfig.maxRetries) {
        throw error;
      }

      const response = (error as AxiosLikeError).response;
      const serverDelay = response ? getServerSuggestedDelay(response.data, response.headers) : null;
      const { delay, source } = computeRetryDelay(retryCount, serverDelay, this.retryConfig);

      if (this.retryConfig.enableLogging) {
        this.logger.log(
          `[Capsara SDK] Retry attempt ${retryCount + 1}/${this.retryConfig.maxRetries} ` +
          `for ${describeFailure(error)} (file download) - waiting ${delay}ms (${source})`
        );
      }

      await sleep(delay);
      return this.downloadFileWithRetry(downloadUrl, retryCount + 1);
    }
  }
}
