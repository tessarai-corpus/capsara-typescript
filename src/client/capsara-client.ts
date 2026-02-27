/** Primary interface for zero-knowledge encrypted file sharing. */

import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios';
import { AuthService } from '../internal/services/auth-service.js';
import { KeyManager } from '../internal/services/key-service.js';
import { LimitsManager } from '../internal/services/limits-service.js';
import { AccountClient, type PublicKeyInfo, type KeyHistoryEntry } from '../internal/services/account-service.js';
import { CapsaService } from '../internal/services/capsa-service.js';
import { DownloadService } from '../internal/services/download-service.js';
import { UploadService } from '../internal/services/upload-service.js';
import { AuditService } from '../internal/services/audit-service.js';
import { DecryptedCapsaCache } from '../internal/capsa-cache.js';
import { generateKeyPair, type GeneratedKeyPair } from '../internal/crypto/key-generator.js';
import { CapsaBuilder } from '../builder/capsa-builder.js';
import { type DecryptedCapsa } from '../internal/decryptor/capsa-decryptor.js';
import {
  createAxiosConfig,
  configureRetryInterceptor,
  createHttpAgent,
  createHttpsAgent,
  DEFAULT_TIMEOUT_CONFIG,
  type HttpTimeoutConfig,
} from '../internal/config/http-client.js';
import type { RetryConfig, RetryLogger } from '../internal/config/retry-interceptor.js';
import type {
  AuthCredentials,
  AuthResponse,
  Capsa,
  SystemLimits,
  CapsaListFilters,
  CapsaListResponse,
  GetAuditEntriesFilters,
  GetAuditEntriesResponse,
  CreateAuditEntryRequest,
  CreateAuditEntryResponse,
} from '../types/index.js';

export interface CapsaraClientOptions {
  credentials?: AuthCredentials;
  accessToken?: string;
  expectedIssuer?: string;
  expectedAudience?: string;
  timeout?: Partial<HttpTimeoutConfig>;
  retry?: RetryConfig;
  maxBatchSize?: number;
  cacheTTL?: number;
  /**
   * Custom user agent string to append to the default SDK user agent.
   * Default: "Capsara-SDK/1.0.0 (Node.js v20.x.x)"
   * If provided, becomes: "Capsara-SDK/1.0.0 (Node.js v20.x.x) YourCustomAgent"
   */
  userAgent?: string;
}

export class CapsaraClient {
  private creatorId: string | null = null;
  private creatorPrivateKey: string | null = null;
  private authService: AuthService;
  private keyManager: KeyManager;
  private limitsManager: LimitsManager;
  private accountClient: AccountClient;
  private capsaService: CapsaService;
  private downloadService: DownloadService;
  private uploadService: UploadService;
  private auditService: AuditService;
  private capsaCache: DecryptedCapsaCache;
  private axiosInstance: AxiosInstance;
  private blobClient: AxiosInstance;
  private timeoutConfig: HttpTimeoutConfig;
  private retryConfig: Required<RetryConfig>;
  private maxBatchSize: number;
  private logger: RetryLogger;
  private refreshPromise: Promise<boolean> | null = null;
  private inFlightCapsaFetches: Map<string, Promise<DecryptedCapsa>> = new Map();

  constructor(baseUrl: string, options?: CapsaraClientOptions) {
    this.timeoutConfig = { ...DEFAULT_TIMEOUT_CONFIG, ...options?.timeout };
    // eslint-disable-next-line no-console
    this.logger = options?.retry?.logger ?? { log: (msg: string) => console.log(msg) };
    this.retryConfig = {
      maxRetries: options?.retry?.maxRetries ?? 3,
      baseDelay: options?.retry?.baseDelay ?? 1000,
      maxDelay: options?.retry?.maxDelay ?? 30000,
      enableLogging: options?.retry?.enableLogging ?? false,
      logger: this.logger,
    };
    this.maxBatchSize = options?.maxBatchSize ?? 150;

    const axiosConfig = createAxiosConfig(baseUrl, this.timeoutConfig.apiTimeout, this.timeoutConfig, options?.userAgent);
    this.axiosInstance = axios.create(axiosConfig);
    configureRetryInterceptor(this.axiosInstance, options?.retry);

    // No auth headers — SAS URL contains credentials
    this.blobClient = axios.create({
      timeout: this.timeoutConfig.downloadTimeout,
      maxContentLength: 1024 * 1024 * 1024, // 1GB
      maxBodyLength: 1024 * 1024 * 1024,
      httpAgent: createHttpAgent(this.timeoutConfig),
      httpsAgent: createHttpsAgent(this.timeoutConfig),
    });

    this.authService = new AuthService(baseUrl, {
      expectedIssuer: options?.expectedIssuer,
      expectedAudience: options?.expectedAudience,
      timeout: options?.timeout,
      retry: options?.retry,
      userAgent: options?.userAgent,
    });

    this.axiosInstance.interceptors.request.use((config) => {
      const token = this.authService.getToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Automatic token refresh on 401
    this.axiosInstance.interceptors.response.use(
      (response) => response,
      async (error: unknown) => {
        const axiosError = error as { response?: { status?: number }; config?: InternalAxiosRequestConfig & { _retry?: boolean } };
        const originalRequest = axiosError.config;

        if (
          axiosError.response?.status === 401 &&
          originalRequest &&
          !originalRequest._retry &&
          this.authService.canRefresh()
        ) {
          originalRequest._retry = true;

          // Single-flight: coalesce concurrent refresh attempts into one request
          if (!this.refreshPromise) {
            this.refreshPromise = this.authService.refresh().finally(() => {
              this.refreshPromise = null;
            });
          }

          const refreshed = await this.refreshPromise;
          if (refreshed) {
            const newToken = this.authService.getToken();
            if (newToken) {
              originalRequest.headers.Authorization = `Bearer ${newToken}`;
            }
            return this.axiosInstance(originalRequest);
          }

          const refreshError = this.authService.getLastRefreshError();
          if (refreshError) {
            return Promise.reject(refreshError);
          }
        }

        if (error instanceof Error) {
          return Promise.reject(error);
        }
        return Promise.reject(new Error(String(error)));
      }
    );

    this.keyManager = new KeyManager(baseUrl, () => this.authService.getToken(), {
      timeout: options?.timeout,
      retry: options?.retry,
    });

    this.limitsManager = new LimitsManager(baseUrl, options?.timeout, options?.retry);
    this.accountClient = new AccountClient(baseUrl, () => this.authService.getToken(), options?.timeout, options?.retry);

    this.capsaService = new CapsaService({
      axiosInstance: this.axiosInstance,
      keyManager: this.keyManager,
    });

    this.downloadService = new DownloadService({
      axiosInstance: this.axiosInstance,
      blobClient: this.blobClient,
      retryConfig: this.retryConfig,
      logger: this.logger,
    });

    this.uploadService = new UploadService({
      baseUrl,
      keyManager: this.keyManager,
      getToken: () => this.authService.getToken(),
      timeoutConfig: this.timeoutConfig,
      retryConfig: this.retryConfig,
      logger: this.logger,
      maxBatchSize: this.maxBatchSize,
      userAgent: options?.userAgent,
    });

    this.auditService = new AuditService({ axiosInstance: this.axiosInstance });

    this.capsaCache = new DecryptedCapsaCache({ ttl: options?.cacheTTL ?? 5 * 60 * 1000 });

    if (options?.credentials) {
      this.login(options.credentials).catch(() => {});
    }
    if (options?.accessToken) {
      this.authService.setToken(options.accessToken);
    }
  }

  async login(credentials: AuthCredentials): Promise<AuthResponse> {
    const response = await this.authService.login(credentials);
    this.creatorId = response.party.id;
    return response;
  }

  async logout(): Promise<boolean> {
    this.capsaCache.clearAll();
    return this.authService.logout();
  }

  isAuthenticated(): boolean {
    return this.authService.isAuthenticated();
  }

  setPrivateKey(privateKey: string): void {
    this.creatorPrivateKey = privateKey;
  }

  async createCapsaBuilder(): Promise<CapsaBuilder> {
    if (!this.creatorId || !this.creatorPrivateKey) {
      throw new Error('Creator identity not set. Call login() and setPrivateKey() first.');
    }
    const limits = await this.limitsManager.getLimits();
    return new CapsaBuilder(this.creatorId, this.creatorPrivateKey, limits);
  }

  async sendCapsas(builders: CapsaBuilder[]): Promise<{
    batchId: string;
    successful: number;
    failed: number;
    partialSuccess?: boolean;
    created: Array<{ packageId: string; index: number }>;
    errors?: Array<{ index: number; packageId: string; error: string }>;
  }> {
    if (!this.creatorId) {
      throw new Error('Creator identity not set. Call login() and setPrivateKey() first.');
    }
    return this.uploadService.sendCapsas(builders, this.creatorId);
  }

  async getCapsa(capsaId: string): Promise<DecryptedCapsa>;
  async getCapsa(capsaId: string, options: { decrypt: false }): Promise<Capsa>;
  async getCapsa(capsaId: string, options: { verifySignature?: boolean }): Promise<DecryptedCapsa>;
  async getCapsa(capsaId: string, options?: { decrypt?: boolean; verifySignature?: boolean }): Promise<DecryptedCapsa | Capsa> {
    if (options?.decrypt === false) {
      return this.capsaService.getCapsa(capsaId);
    }

    // Deduplicates concurrent requests for the same capsaId
    return this.getOrCreateCapsaFetch(capsaId, options);
  }

  private getOrCreateCapsaFetch(
    capsaId: string,
    options?: { verifySignature?: boolean }
  ): Promise<DecryptedCapsa> {
    const existing = this.inFlightCapsaFetches.get(capsaId);
    if (existing) {
      return existing;
    }

    // Must set in map synchronously before any await to prevent races
    const fetchPromise = this.fetchAndDecryptCapsa(capsaId, options).finally(() => {
      this.inFlightCapsaFetches.delete(capsaId);
    });
    this.inFlightCapsaFetches.set(capsaId, fetchPromise);

    return fetchPromise;
  }

  private async fetchAndDecryptCapsa(
    capsaId: string,
    options?: { verifySignature?: boolean }
  ): Promise<DecryptedCapsa> {
    if (!this.creatorPrivateKey) {
      throw new Error('Private key required. Call setPrivateKey() first.');
    }

    const verifySignature = options?.verifySignature !== false; // default true
    const decrypted = await this.capsaService.getDecryptedCapsa(capsaId, this.creatorPrivateKey, verifySignature);

    // Zeroed on cache eviction
    const masterKeyBuffer = decrypted._masterKey;
    if (masterKeyBuffer) {
      this.capsaCache.set(capsaId, masterKeyBuffer, decrypted.files.map(f => ({
        fileId: f.fileId,
        iv: f.iv,
        authTag: f.authTag,
        compressed: f.compressed,
        encryptedFilename: f.encryptedFilename,
        filenameIV: f.filenameIV,
        filenameAuthTag: f.filenameAuthTag,
      })));
    }

    return decrypted;
  }

  async listCapsas(filters?: CapsaListFilters): Promise<CapsaListResponse> {
    return this.capsaService.listCapsas(filters);
  }

  async deleteCapsa(capsaId: string): Promise<void> {
    this.capsaCache.clear(capsaId);
    return this.capsaService.deleteCapsa(capsaId);
  }

  async downloadFile(capsaId: string, fileId: string): Promise<{ data: Buffer; filename: string }> {
    let masterKey = this.capsaCache.getMasterKey(capsaId);
    let fileMetadata = this.capsaCache.getFileMetadata(capsaId, fileId);

    if (!masterKey || !fileMetadata) {
      await this.getCapsa(capsaId);
      masterKey = this.capsaCache.getMasterKey(capsaId);
      fileMetadata = this.capsaCache.getFileMetadata(capsaId, fileId);
    }

    if (!masterKey || !fileMetadata) {
      throw new Error(`File ${fileId} not found in capsa ${capsaId}`);
    }

    return this.downloadService.downloadAndDecryptFile(capsaId, fileId, masterKey, fileMetadata);
  }

  async getAuditEntries(capsaId: string, filters?: GetAuditEntriesFilters): Promise<GetAuditEntriesResponse> {
    return this.auditService.getAuditEntries(capsaId, filters);
  }

  async createAuditEntry(capsaId: string, entry: CreateAuditEntryRequest): Promise<CreateAuditEntryResponse> {
    return this.auditService.createAuditEntry(capsaId, entry);
  }

  async getCurrentPublicKey(): Promise<PublicKeyInfo | null> {
    return this.accountClient.getCurrentPublicKey();
  }

  async addPublicKey(publicKey: string, fingerprint: string, reason?: string): Promise<PublicKeyInfo> {
    return this.accountClient.addPublicKey(publicKey, fingerprint, reason);
  }

  async getKeyHistory(): Promise<KeyHistoryEntry[]> {
    return this.accountClient.getKeyHistory();
  }

  async rotateKey(): Promise<{ keyPair: GeneratedKeyPair; serverInfo: PublicKeyInfo }> {
    return this.accountClient.rotateKey();
  }

  async getLimits(): Promise<SystemLimits> {
    return this.limitsManager.getLimits();
  }

  static async generateKeyPair(): Promise<GeneratedKeyPair> {
    return generateKeyPair();
  }

  clearCache(): void {
    this.capsaCache.clearAll();
  }

  /** Release all resources and securely clear cached keys. */
  async destroy(): Promise<void> {
    this.capsaCache.clearAll();
    this.inFlightCapsaFetches.clear();
    this.refreshPromise = null;
    this.creatorId = null;
    this.creatorPrivateKey = null;

    // Fire-and-forget server-side logout
    await this.authService.logout().catch(() => {});
  }
}
