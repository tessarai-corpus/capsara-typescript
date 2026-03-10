/** File download and decryption service. */

import type { AxiosInstance } from 'axios';
import { decryptFilename } from '../decryptor/capsa-decryptor.js';
import { decryptAESRaw } from '../crypto/primitives.js';
import { decompressData } from '../crypto/compression.js';
import { CapsaraCapsaError } from '../../errors/capsa-error.js';
import type { AxiosLikeError } from '../../errors/capsara-error.js';
import type { RetryConfig, RetryLogger } from '../config/retry-interceptor.js';

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
  data: Buffer;
  filename: string;
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

  /**
   * Get download URL for encrypted file
   * @param capsaId - Capsa ID
   * @param fileId - File ID
   * @param expiresInMinutes - URL expiration in minutes (default: 60)
   * @returns Download URL and expiration
   */
  async getFileDownloadUrl(
    capsaId: string,
    fileId: string,
    expiresInMinutes = 60
  ): Promise<{ downloadUrl: string; expiresAt: string }> {
    try {
      const response = await this.http.get<{
        fileId: string;
        downloadUrl: string;
        expiresAt: string;
      }>(`/api/capsas/${capsaId}/files/${fileId}/download`, {
        params: { expires: expiresInMinutes },
      });

      return {
        downloadUrl: response.data.downloadUrl,
        expiresAt: response.data.expiresAt,
      };
    } catch (error) {
      throw CapsaraCapsaError.fromApiError(error as AxiosLikeError);
    }
  }

  /**
   * Download encrypted file from blob storage
   * @param capsaId - Capsa ID
   * @param fileId - File ID
   * @returns Encrypted file data
   */
  async downloadEncryptedFile(capsaId: string, fileId: string): Promise<Buffer> {
    const { downloadUrl } = await this.getFileDownloadUrl(capsaId, fileId);
    return this.downloadFileWithRetry(downloadUrl, 0);
  }

  /**
   * Download and decrypt file
   * @param capsaId - Capsa ID
   * @param fileId - File ID
   * @param masterKey - Decrypted master key (raw Buffer)
   * @param metadata - File metadata for decryption
   * @returns Decrypted file data and filename
   */
  async downloadAndDecryptFile(
    capsaId: string,
    fileId: string,
    masterKey: Buffer,
    metadata: FileMetadata
  ): Promise<DecryptedFileResult> {
    try {
      const encryptedData = await this.downloadEncryptedFile(capsaId, fileId);

      // Decrypt using raw Buffer APIs to avoid base64 round-trip overhead
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

      return { data: decryptedData, filename };
    } catch (error) {
      // Wrap error with capsaId and fileId context for debugging
      throw CapsaraCapsaError.downloadFailed(capsaId, fileId, error);
    }
  }

  /** Download file with retry logic. */
  private async downloadFileWithRetry(downloadUrl: string, retryCount: number): Promise<Buffer> {
    try {
      const response = await this.blobDownloadClient.get<ArrayBuffer>(downloadUrl, {
        responseType: 'arraybuffer',
      });

      return Buffer.from(response.data);
    } catch (error) {
      const axiosError = error as AxiosLikeError;
      const status = axiosError.response?.status;
      const isRetryable = status === 503 || status === 429;

      if (isRetryable && retryCount < this.retryConfig.maxRetries) {
        const retryDelay = this.calculateRetryDelay(axiosError, retryCount, status);

        if (this.retryConfig.enableLogging) {
          this.logger.log(
            `[Capsara SDK] Retry attempt ${retryCount + 1}/${this.retryConfig.maxRetries} ` +
            `for ${status} error (file download) - waiting ${Math.floor(retryDelay)}ms`
          );
        }

        await new Promise(resolve => globalThis.setTimeout(resolve, retryDelay));
        return this.downloadFileWithRetry(downloadUrl, retryCount + 1);
      }

      throw error;
    }
  }

  /**
   * Calculate retry delay with exponential backoff
   */
  private calculateRetryDelay(error: AxiosLikeError, retryCount: number, _status: number | undefined): number {
    const responseData = error.response?.data as Record<string, unknown> | undefined;
    const errorObj = responseData?.error as Record<string, unknown> | undefined;
    const serverDelay = errorObj?.retryAfter;

    if (typeof serverDelay === 'number') {
      return Math.min(serverDelay * 1000, this.retryConfig.maxDelay);
    }

    // Exponential backoff with jitter
    const exponentialDelay = this.retryConfig.baseDelay * Math.pow(2, retryCount);
    const jitter = Math.random() * 0.3 * exponentialDelay;
    return Math.min(exponentialDelay + jitter, this.retryConfig.maxDelay);
  }
}
