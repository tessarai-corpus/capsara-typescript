/** Primary interface for zero-knowledge encrypted file sharing. */

import * as crypto from 'crypto';
import axios, { type AxiosInstance } from 'axios';
import { AuthService } from '../internal/services/auth-service.js';
import { KeyManager } from '../internal/services/key-service.js';
import { LimitsManager } from '../internal/services/limits-service.js';
import {
  AccountClient,
  type PublicKeyInfo,
  type KeyHistoryEntry,
  type RotateKeyOptions,
} from '../internal/services/account-service.js';
import { CapsaService } from '../internal/services/capsa-service.js';
import { DownloadService, type DecryptedFileResult } from '../internal/services/download-service.js';
import { UploadService, type SendResult } from '../internal/services/upload-service.js';
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
import { addTokenRefreshInterceptor, createTokenRefresher, type TokenRefresher } from '../internal/config/token-refresh.js';
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
import { CapsaraError } from '../errors/capsara-error.js';
import { CapsaraCapsaError } from '../errors/capsa-error.js';
import { calculatePrivateKeyFingerprint } from '../internal/crypto/key-generator.js';

function isUsableRsaPrivateKey(privateKey: string): boolean {
  try {
    const key = crypto.createPrivateKey({ key: privateKey, format: 'pem' });
    return key.asymmetricKeyType === 'rsa' && calculatePrivateKeyFingerprint(key).length > 0;
  } catch {
    return false;
  }
}

function notLoggedIn(): CapsaraError {
  return new CapsaraError('Creator identity not set. Call login() first.', 'NOT_LOGGED_IN', 0);
}

function missingPrivateKey(): CapsaraError {
  return new CapsaraError('Private key required. Call setPrivateKey() first.', 'MISSING_PRIVATE_KEY', 0);
}

function assertUsablePrivateKey(privateKey: string, which: 'current' | 'previous'): void {
  if (!isUsableRsaPrivateKey(privateKey)) {
    throw new CapsaraError(`The ${which} private key is not a usable RSA private key PEM.`, 'INVALID_PRIVATE_KEY', 0);
  }
}

export interface CapsaraClientOptions {
  accessToken?: string;
  expectedIssuer?: string;
  expectedAudience?: string;
  timeout?: Partial<HttpTimeoutConfig>;
  retry?: RetryConfig;
  maxBatchSize?: number;
  cacheTTL?: number;
  previousPrivateKeys?: string[];
  /**
   * Custom user agent string to append to the default SDK user agent.
   * Default: "Capsara-SDK-typescript/<sdk version> (Node.js <node version>)"
   * If provided, becomes: "Capsara-SDK-typescript/<sdk version> (Node.js <node version>) YourCustomAgent"
   */
  userAgent?: string;
}

export class CapsaraClient {
  private creatorId: string | null = null;
  private creatorPrivateKey: string | null = null;
  private previousPrivateKeys: string[] = [];
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
  private tokenRefresher: TokenRefresher;
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

    this.tokenRefresher = createTokenRefresher(this.authService);
    addTokenRefreshInterceptor(this.axiosInstance, this.tokenRefresher);

    this.keyManager = new KeyManager(baseUrl, () => this.authService.getToken(), {
      timeout: options?.timeout,
      retry: options?.retry,
      tokenRefresher: this.tokenRefresher,
      userAgent: options?.userAgent,
    });

    this.limitsManager = new LimitsManager(baseUrl, options?.timeout, options?.retry, options?.userAgent);
    this.accountClient = new AccountClient(
      baseUrl,
      () => this.authService.getToken(),
      options?.timeout,
      options?.retry,
      this.tokenRefresher,
      options?.userAgent
    );

    this.capsaService = new CapsaService({
      axiosInstance: this.axiosInstance,
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
      tokenRefresher: this.tokenRefresher,
      timeoutConfig: this.timeoutConfig,
      retryConfig: this.retryConfig,
      logger: this.logger,
      maxBatchSize: this.maxBatchSize,
      getLimits: () => this.limitsManager.getLimits(),
      userAgent: options?.userAgent,
    });

    this.auditService = new AuditService({ axiosInstance: this.axiosInstance });

    this.capsaCache = new DecryptedCapsaCache({ ttl: options?.cacheTTL ?? 5 * 60 * 1000 });

    for (const previousKey of options?.previousPrivateKeys ?? []) {
      this.addPreviousPrivateKey(previousKey);
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
    assertUsablePrivateKey(privateKey, 'current');
    this.creatorPrivateKey = privateKey;
  }

  addPreviousPrivateKey(privateKey: string): void {
    assertUsablePrivateKey(privateKey, 'previous');
    if (!this.previousPrivateKeys.includes(privateKey)) {
      this.previousPrivateKeys.push(privateKey);
    }
  }

  async createCapsaBuilder(): Promise<CapsaBuilder> {
    if (!this.creatorId) {
      throw notLoggedIn();
    }
    if (!this.creatorPrivateKey) {
      throw missingPrivateKey();
    }
    const limits = await this.limitsManager.getLimits();
    return new CapsaBuilder(this.creatorId, this.creatorPrivateKey, limits);
  }

  async sendCapsas(builders: CapsaBuilder[]): Promise<SendResult> {
    if (!this.creatorId) {
      throw notLoggedIn();
    }
    return this.uploadService.sendCapsas(builders, this.creatorId);
  }

  async getCapsa(capsaId: string): Promise<DecryptedCapsa>;
  async getCapsa(capsaId: string, options: { decrypt: false }): Promise<Capsa>;
  async getCapsa(capsaId: string, options: { decrypt: true }): Promise<DecryptedCapsa>;
  async getCapsa(capsaId: string, options?: { decrypt?: boolean }): Promise<DecryptedCapsa | Capsa> {
    if (options?.decrypt === false) {
      return this.capsaService.getCapsa(capsaId);
    }

    // Deduplicates concurrent requests for the same capsaId
    return this.getOrCreateCapsaFetch(capsaId);
  }

  private getOrCreateCapsaFetch(capsaId: string): Promise<DecryptedCapsa> {
    const existing = this.inFlightCapsaFetches.get(capsaId);
    if (existing) {
      return existing;
    }

    // Must set in map synchronously before any await to prevent races
    const fetchPromise = this.fetchAndDecryptCapsa(capsaId).finally(() => {
      this.inFlightCapsaFetches.delete(capsaId);
    });
    this.inFlightCapsaFetches.set(capsaId, fetchPromise);

    return fetchPromise;
  }

  private async fetchAndDecryptCapsa(capsaId: string): Promise<DecryptedCapsa> {
    if (!this.creatorPrivateKey) {
      throw missingPrivateKey();
    }

    const decrypted = await this.capsaService.getDecryptedCapsa(capsaId, this.creatorPrivateKey, {
      ...(this.creatorId && { partyId: this.creatorId }),
      previousPrivateKeys: this.previousPrivateKeys,
    });

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

  /**
   * Download and decrypt a file.
   *
   * The result's `filename` is the name the sender supplied and is untrusted.
   * Write the file using `safeFilename`, joined to a directory you chose.
   * @param capsaId - Capsa ID
   * @param fileId - File ID
   */
  async downloadFile(capsaId: string, fileId: string): Promise<DecryptedFileResult> {
    let masterKey = this.capsaCache.getMasterKey(capsaId);
    let fileMetadata = this.capsaCache.getFileMetadata(capsaId, fileId);

    if (!masterKey || !fileMetadata) {
      await this.getCapsa(capsaId);
      masterKey = this.capsaCache.getMasterKey(capsaId);
      fileMetadata = this.capsaCache.getFileMetadata(capsaId, fileId);
    }

    if (!masterKey || !fileMetadata) {
      throw new CapsaraCapsaError(`File ${fileId} not found in capsa ${capsaId}`, 'FILE_NOT_FOUND', 0, { capsaId, fileId });
    }

    const ownMasterKey = Buffer.from(masterKey);
    try {
      return await this.downloadService.downloadAndDecryptFile(capsaId, fileId, ownMasterKey, fileMetadata);
    } finally {
      ownMasterKey.fill(0);
    }
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

  async rotateKey(options?: RotateKeyOptions): Promise<{ keyPair: GeneratedKeyPair; serverInfo: PublicKeyInfo }> {
    const result = await this.accountClient.rotateKey(options);
    const oldPrivateKey = this.creatorPrivateKey;
    if (oldPrivateKey && oldPrivateKey !== result.keyPair.privateKey && !this.previousPrivateKeys.includes(oldPrivateKey)) {
      this.previousPrivateKeys.push(oldPrivateKey);
    }
    this.creatorPrivateKey = result.keyPair.privateKey;
    this.capsaCache.clearAll();
    return result;
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
    this.creatorId = null;
    this.creatorPrivateKey = null;
    this.previousPrivateKeys = [];

    // Fire-and-forget server-side logout
    await this.authService.logout().catch(() => {});
  }
}
