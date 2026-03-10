// In-memory cache for decrypted capsa master keys and file metadata.
// Security: master keys stored in memory only, cleared on logout, TTL-based expiry.

/** Decrypted file metadata for download operations. */
export interface CachedFileMetadata {
  iv: string;
  authTag: string;
  compressed?: boolean;
  encryptedFilename: string;
  filenameIV: string;
  filenameAuthTag: string;
}

/** Cached capsa entry with master key and file metadata. */
export interface CachedCapsa {
  /** Decrypted master key (zeroed on eviction). */
  masterKey: Buffer;
  files: Map<string, CachedFileMetadata>;
  cachedAt: number;
  expiresAt: number;
}

export interface CapsaCacheConfig {
  /** Cache TTL in milliseconds (default: 5 minutes). */
  ttl?: number;
  /** Maximum number of cached capsas (default: 100). */
  maxSize?: number;
}

const DEFAULT_CONFIG: Required<CapsaCacheConfig> = {
  ttl: 5 * 60 * 1000,  // 5 minutes
  maxSize: 100,
};

/**
 * Caches master keys after getCapsa() to avoid redundant RSA-4096 decryption
 * on each file download.
 */
export class DecryptedCapsaCache {
  private cache: Map<string, CachedCapsa> = new Map();
  private config: Required<CapsaCacheConfig>;

  constructor(config?: CapsaCacheConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  set(capsaId: string, masterKey: Buffer, files: Array<{ fileId: string } & CachedFileMetadata>): void {
    if (this.cache.size >= this.config.maxSize) {
      this.evictOldest();
    }

    const now = Date.now();
    const fileMap = new Map<string, CachedFileMetadata>();
    for (const file of files) {
      fileMap.set(file.fileId, {
        iv: file.iv,
        authTag: file.authTag,
        compressed: file.compressed,
        encryptedFilename: file.encryptedFilename,
        filenameIV: file.filenameIV,
        filenameAuthTag: file.filenameAuthTag,
      });
    }

    this.cache.set(capsaId, {
      masterKey,
      files: fileMap,
      cachedAt: now,
      expiresAt: now + this.config.ttl,
    });
  }

  get(capsaId: string): CachedCapsa | null {
    const entry = this.cache.get(capsaId);
    if (!entry) {
      return null;
    }

    if (Date.now() > entry.expiresAt) {
      entry.masterKey.fill(0);
      this.cache.delete(capsaId);
      return null;
    }

    return entry;
  }

  getMasterKey(capsaId: string): Buffer | null {
    const entry = this.get(capsaId);
    return entry?.masterKey ?? null;
  }

  getFileMetadata(capsaId: string, fileId: string): CachedFileMetadata | null {
    const entry = this.get(capsaId);
    return entry?.files.get(fileId) ?? null;
  }

  has(capsaId: string): boolean {
    return this.get(capsaId) !== null;
  }

  /** Zeroes master key and removes the entry. */
  clear(capsaId: string): void {
    const entry = this.cache.get(capsaId);
    if (entry) {
      entry.masterKey.fill(0);
      this.cache.delete(capsaId);
    }
  }

  /** Zeroes all master keys and clears the cache. */
  clearAll(): void {
    this.cache.forEach(entry => entry.masterKey.fill(0));
    this.cache.clear();
  }

  clearMasterKey(capsaId: string): void {
    const entry = this.cache.get(capsaId);
    if (entry) {
      entry.masterKey.fill(0);
      this.cache.delete(capsaId);
    }
  }

  get size(): number {
    return this.cache.size;
  }

  prune(): void {
    const now = Date.now();
    const toDelete: string[] = [];
    this.cache.forEach((entry, capsaId) => {
      if (now > entry.expiresAt) {
        entry.masterKey.fill(0);
        toDelete.push(capsaId);
      }
    });
    toDelete.forEach(id => this.cache.delete(id));
  }

  private evictOldest(): void {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    this.cache.forEach((entry, key) => {
      if (entry.cachedAt < oldestTime) {
        oldestTime = entry.cachedAt;
        oldestKey = key;
      }
    });

    if (oldestKey) {
      const entry = this.cache.get(oldestKey);
      if (entry) {
        entry.masterKey.fill(0);
      }
      this.cache.delete(oldestKey);
    }
  }
}

export function createCapsaCache(config?: CapsaCacheConfig): DecryptedCapsaCache {
  return new DecryptedCapsaCache(config);
}
