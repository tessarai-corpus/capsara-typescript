/// <reference types="vitest/globals" />
/**
 * Tests for DecryptedCapsaCache internal module
 * @module tests/unit/internal/capsa-cache.test
 *
 * Tests the capsa cache functionality including:
 * - Cache storage and retrieval (set/get methods)
 * - Master key access (getMasterKey)
 * - File metadata access (getFileMetadata)
 * - Cache membership checking (has)
 * - Cache clearing (clear, clearAll, clearMasterKey)
 * - Cache size tracking (size getter)
 * - TTL-based expiration behavior
 * - LRU eviction when maxSize exceeded
 * - Pruning of expired entries
 * - Factory function (createCapsaCache)
 */

import {
  DecryptedCapsaCache,
  createCapsaCache,
  type CachedFileMetadata,
  type CachedCapsa,
  type CapsaCacheConfig,
} from '../../../src/internal/capsa-cache.js';

/**
 * Helper to create test file metadata
 */
function createTestFileMetadata(overrides?: Partial<CachedFileMetadata>): CachedFileMetadata {
  return {
    iv: 'test-iv-base64',
    authTag: 'test-auth-tag-base64',
    compressed: false,
    encryptedFilename: 'encrypted-filename-base64',
    filenameIV: 'filename-iv-base64',
    filenameAuthTag: 'filename-auth-tag-base64',
    ...overrides,
  };
}

/**
 * Helper to create test file with ID
 */
function createTestFile(
  fileId: string,
  overrides?: Partial<CachedFileMetadata>
): { fileId: string } & CachedFileMetadata {
  return {
    fileId,
    ...createTestFileMetadata(overrides),
  };
}

describe('DecryptedCapsaCache', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Constructor', () => {
    it('should create cache with default configuration', () => {
      const cache = new DecryptedCapsaCache();
      expect(cache.size).toBe(0);
    });

    it('should create cache with custom TTL', () => {
      const customTtl = 60000; // 1 minute
      const cache = new DecryptedCapsaCache({ ttl: customTtl });

      const masterKey = Buffer.from('test-master-key');
      cache.set('capsa-1', masterKey, [createTestFile('file-1')]);

      // Should exist immediately
      expect(cache.has('capsa-1')).toBe(true);

      // Advance time just before TTL
      vi.advanceTimersByTime(customTtl - 1);
      expect(cache.has('capsa-1')).toBe(true);

      // Advance past TTL
      vi.advanceTimersByTime(2);
      expect(cache.has('capsa-1')).toBe(false);
    });

    it('should create cache with custom maxSize', () => {
      const cache = new DecryptedCapsaCache({ maxSize: 2 });

      cache.set('capsa-1', Buffer.from('key-1'), [createTestFile('file-1')]);
      cache.set('capsa-2', Buffer.from('key-2'), [createTestFile('file-2')]);
      expect(cache.size).toBe(2);

      // Adding third should evict oldest
      cache.set('capsa-3', Buffer.from('key-3'), [createTestFile('file-3')]);
      expect(cache.size).toBe(2);
      expect(cache.has('capsa-1')).toBe(false);
      expect(cache.has('capsa-2')).toBe(true);
      expect(cache.has('capsa-3')).toBe(true);
    });

    it('should create cache with both custom TTL and maxSize', () => {
      const cache = new DecryptedCapsaCache({ ttl: 10000, maxSize: 5 });

      for (let i = 0; i < 5; i++) {
        cache.set(`capsa-${i}`, Buffer.from(`key-${i}`), [createTestFile(`file-${i}`)]);
      }
      expect(cache.size).toBe(5);

      // Verify TTL works with custom config
      vi.advanceTimersByTime(10001);
      expect(cache.has('capsa-0')).toBe(false);
    });

    it('should merge provided config with defaults', () => {
      // Only provide ttl, maxSize should use default (100)
      const cache = new DecryptedCapsaCache({ ttl: 1000 });

      // Can add up to 100 entries (default maxSize)
      for (let i = 0; i < 100; i++) {
        cache.set(`capsa-${i}`, Buffer.from(`key-${i}`), []);
      }
      expect(cache.size).toBe(100);

      // 101st should trigger eviction
      cache.set('capsa-100', Buffer.from('key-100'), []);
      expect(cache.size).toBe(100);
    });

    it('should accept empty config object', () => {
      const cache = new DecryptedCapsaCache({});
      cache.set('capsa-1', Buffer.from('key-1'), []);
      expect(cache.has('capsa-1')).toBe(true);
    });
  });

  describe('set() Method', () => {
    it('should store capsa with master key and files', () => {
      const cache = new DecryptedCapsaCache();
      const masterKey = Buffer.from('base64-encoded-master-key');
      const files = [
        createTestFile('file-1'),
        createTestFile('file-2'),
      ];

      cache.set('capsa-123', masterKey, files);

      expect(cache.size).toBe(1);
      expect(cache.has('capsa-123')).toBe(true);
    });

    it('should store capsa with empty files array', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-empty', Buffer.from('master-key'), []);

      const result = cache.get('capsa-empty');
      expect(result).not.toBeNull();
      expect(result!.files.size).toBe(0);
    });

    it('should overwrite existing entry with same capsaId', () => {
      const cache = new DecryptedCapsaCache();

      cache.set('capsa-1', Buffer.from('old-key'), [createTestFile('old-file')]);
      cache.set('capsa-1', Buffer.from('new-key'), [createTestFile('new-file')]);

      expect(cache.size).toBe(1);
      expect(cache.getMasterKey('capsa-1')).toEqual(Buffer.from('new-key'));
      expect(cache.getFileMetadata('capsa-1', 'old-file')).toBeNull();
      expect(cache.getFileMetadata('capsa-1', 'new-file')).not.toBeNull();
    });

    it('should store correct timestamps', () => {
      const cache = new DecryptedCapsaCache({ ttl: 300000 }); // 5 minutes
      const now = Date.now();

      cache.set('capsa-1', Buffer.from('key'), []);

      const entry = cache.get('capsa-1');
      expect(entry).not.toBeNull();
      expect(entry!.cachedAt).toBe(now);
      expect(entry!.expiresAt).toBe(now + 300000);
    });

    it('should store file metadata correctly excluding fileId', () => {
      const cache = new DecryptedCapsaCache();
      const fileData: { fileId: string } & CachedFileMetadata = {
        fileId: 'file-123',
        iv: 'unique-iv',
        authTag: 'unique-auth-tag',
        compressed: true,
        encryptedFilename: 'encrypted-name',
        filenameIV: 'fn-iv',
        filenameAuthTag: 'fn-auth-tag',
      };

      cache.set('capsa-1', Buffer.from('key'), [fileData]);

      const metadata = cache.getFileMetadata('capsa-1', 'file-123');
      expect(metadata).not.toBeNull();
      expect(metadata!.iv).toBe('unique-iv');
      expect(metadata!.authTag).toBe('unique-auth-tag');
      expect(metadata!.compressed).toBe(true);
      expect(metadata!.encryptedFilename).toBe('encrypted-name');
      expect(metadata!.filenameIV).toBe('fn-iv');
      expect(metadata!.filenameAuthTag).toBe('fn-auth-tag');
      // fileId should not be in the stored metadata
      expect((metadata as Record<string, unknown>)['fileId']).toBeUndefined();
    });

    it('should handle file with compressed undefined', () => {
      const cache = new DecryptedCapsaCache();
      const file = createTestFile('file-1');
      delete (file as Partial<CachedFileMetadata>).compressed;

      cache.set('capsa-1', Buffer.from('key'), [file]);

      const metadata = cache.getFileMetadata('capsa-1', 'file-1');
      expect(metadata).not.toBeNull();
      expect(metadata!.compressed).toBeUndefined();
    });

    it('should handle multiple files with different metadata', () => {
      const cache = new DecryptedCapsaCache();
      const files = [
        createTestFile('file-1', { iv: 'iv-1', compressed: false }),
        createTestFile('file-2', { iv: 'iv-2', compressed: true }),
        createTestFile('file-3', { iv: 'iv-3', compressed: false }),
      ];

      cache.set('capsa-1', Buffer.from('key'), files);

      expect(cache.getFileMetadata('capsa-1', 'file-1')!.iv).toBe('iv-1');
      expect(cache.getFileMetadata('capsa-1', 'file-2')!.iv).toBe('iv-2');
      expect(cache.getFileMetadata('capsa-1', 'file-3')!.iv).toBe('iv-3');
      expect(cache.getFileMetadata('capsa-1', 'file-2')!.compressed).toBe(true);
    });

    describe('Eviction Behavior', () => {
      it('should evict oldest entry when maxSize is reached', () => {
        const cache = new DecryptedCapsaCache({ maxSize: 3 });

        cache.set('capsa-1', Buffer.from('key-1'), []);
        vi.advanceTimersByTime(100);
        cache.set('capsa-2', Buffer.from('key-2'), []);
        vi.advanceTimersByTime(100);
        cache.set('capsa-3', Buffer.from('key-3'), []);

        expect(cache.size).toBe(3);

        // Adding fourth should evict capsa-1 (oldest)
        vi.advanceTimersByTime(100);
        cache.set('capsa-4', Buffer.from('key-4'), []);

        expect(cache.size).toBe(3);
        expect(cache.has('capsa-1')).toBe(false);
        expect(cache.has('capsa-2')).toBe(true);
        expect(cache.has('capsa-3')).toBe(true);
        expect(cache.has('capsa-4')).toBe(true);
      });

      it('should evict oldest when adding same number as maxSize', () => {
        const cache = new DecryptedCapsaCache({ maxSize: 1 });

        cache.set('capsa-1', Buffer.from('key-1'), []);
        expect(cache.size).toBe(1);

        vi.advanceTimersByTime(10);
        cache.set('capsa-2', Buffer.from('key-2'), []);
        expect(cache.size).toBe(1);
        expect(cache.has('capsa-1')).toBe(false);
        expect(cache.has('capsa-2')).toBe(true);
      });

      it('should correctly identify oldest entry for eviction', () => {
        const cache = new DecryptedCapsaCache({ maxSize: 3 });

        // Add entries with time gaps
        cache.set('capsa-oldest', Buffer.from('key-oldest'), []);
        vi.advanceTimersByTime(1000);
        cache.set('capsa-middle', Buffer.from('key-middle'), []);
        vi.advanceTimersByTime(1000);
        cache.set('capsa-newest', Buffer.from('key-newest'), []);
        vi.advanceTimersByTime(1000);

        // Force eviction
        cache.set('capsa-new', Buffer.from('key-new'), []);

        expect(cache.has('capsa-oldest')).toBe(false);
        expect(cache.has('capsa-middle')).toBe(true);
        expect(cache.has('capsa-newest')).toBe(true);
        expect(cache.has('capsa-new')).toBe(true);
      });

      it('should not evict when updating existing entry (no size increase)', () => {
        const cache = new DecryptedCapsaCache({ maxSize: 2 });

        cache.set('capsa-1', Buffer.from('key-1'), []);
        vi.advanceTimersByTime(100);
        cache.set('capsa-2', Buffer.from('key-2'), []);

        expect(cache.size).toBe(2);

        // Update existing entry
        vi.advanceTimersByTime(100);
        cache.set('capsa-1', Buffer.from('updated-key-1'), []);

        expect(cache.size).toBe(2);
        expect(cache.has('capsa-1')).toBe(true);
        expect(cache.has('capsa-2')).toBe(true);
        expect(cache.getMasterKey('capsa-1')).toEqual(Buffer.from('updated-key-1'));
      });
    });
  });

  describe('get() Method', () => {
    it('should return cached capsa when valid', () => {
      const cache = new DecryptedCapsaCache();
      const masterKey = Buffer.from('test-master-key');
      const files = [createTestFile('file-1')];

      cache.set('capsa-1', masterKey, files);

      const result = cache.get('capsa-1');
      expect(result).not.toBeNull();
      expect(result!.masterKey).toBe(masterKey);
      expect(result!.files.size).toBe(1);
      expect(result!.files.get('file-1')).toBeDefined();
    });

    it('should return null for non-existent capsaId', () => {
      const cache = new DecryptedCapsaCache();
      expect(cache.get('non-existent')).toBeNull();
    });

    it('should return null for expired entry', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1000 });
      cache.set('capsa-1', Buffer.from('key'), []);

      expect(cache.get('capsa-1')).not.toBeNull();

      vi.advanceTimersByTime(1001);

      expect(cache.get('capsa-1')).toBeNull();
    });

    it('should delete expired entry when accessed', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1000 });
      cache.set('capsa-1', Buffer.from('key'), []);
      cache.set('capsa-2', Buffer.from('key'), []);

      expect(cache.size).toBe(2);

      vi.advanceTimersByTime(1001);

      // Accessing expired entry should delete it
      cache.get('capsa-1');
      expect(cache.size).toBe(1);
    });

    it('should return entry when exactly at expiry time', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1000 });
      cache.set('capsa-1', Buffer.from('key'), []);

      vi.advanceTimersByTime(1000);

      // At exactly expiresAt, Date.now() === entry.expiresAt, so not > expiresAt
      expect(cache.get('capsa-1')).not.toBeNull();
    });

    it('should return full CachedCapsa structure', () => {
      const cache = new DecryptedCapsaCache({ ttl: 5000 });
      const now = Date.now();

      cache.set('capsa-1', Buffer.from('master-key'), [
        createTestFile('file-1', { iv: 'iv-1' }),
        createTestFile('file-2', { iv: 'iv-2' }),
      ]);

      const result = cache.get('capsa-1');
      expect(result).toEqual({
        masterKey: Buffer.from('master-key'),
        files: expect.any(Map),
        cachedAt: now,
        expiresAt: now + 5000,
      });
      expect(result!.files.size).toBe(2);
    });
  });

  describe('getMasterKey() Method', () => {
    it('should return master key for cached capsa', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('secret-master-key'), []);

      expect(cache.getMasterKey('capsa-1')).toEqual(Buffer.from('secret-master-key'));
    });

    it('should return null for non-existent capsaId', () => {
      const cache = new DecryptedCapsaCache();
      expect(cache.getMasterKey('non-existent')).toBeNull();
    });

    it('should return null for expired entry', () => {
      const cache = new DecryptedCapsaCache({ ttl: 500 });
      cache.set('capsa-1', Buffer.from('key'), []);

      vi.advanceTimersByTime(501);

      expect(cache.getMasterKey('capsa-1')).toBeNull();
    });

    it('should return master key with special characters', () => {
      const cache = new DecryptedCapsaCache();
      const specialKey = Buffer.from('base64+key/with==padding');
      cache.set('capsa-1', specialKey, []);

      expect(cache.getMasterKey('capsa-1')).toEqual(specialKey);
    });

    it('should return empty buffer master key if stored', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from(''), []);

      expect(cache.getMasterKey('capsa-1')).toEqual(Buffer.from(''));
    });
  });

  describe('getFileMetadata() Method', () => {
    it('should return file metadata for valid capsa and file', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key'), [
        createTestFile('file-1', { iv: 'specific-iv' }),
      ]);

      const metadata = cache.getFileMetadata('capsa-1', 'file-1');
      expect(metadata).not.toBeNull();
      expect(metadata!.iv).toBe('specific-iv');
    });

    it('should return null for non-existent capsaId', () => {
      const cache = new DecryptedCapsaCache();
      expect(cache.getFileMetadata('non-existent', 'file-1')).toBeNull();
    });

    it('should return null for non-existent fileId', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key'), [createTestFile('file-1')]);

      expect(cache.getFileMetadata('capsa-1', 'non-existent-file')).toBeNull();
    });

    it('should return null for expired capsa', () => {
      const cache = new DecryptedCapsaCache({ ttl: 500 });
      cache.set('capsa-1', Buffer.from('key'), [createTestFile('file-1')]);

      vi.advanceTimersByTime(501);

      expect(cache.getFileMetadata('capsa-1', 'file-1')).toBeNull();
    });

    it('should return correct file from multiple files', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key'), [
        createTestFile('file-1', { iv: 'iv-1', compressed: false }),
        createTestFile('file-2', { iv: 'iv-2', compressed: true }),
        createTestFile('file-3', { iv: 'iv-3', compressed: false }),
      ]);

      const file2 = cache.getFileMetadata('capsa-1', 'file-2');
      expect(file2!.iv).toBe('iv-2');
      expect(file2!.compressed).toBe(true);
    });

    it('should return metadata with all required fields', () => {
      const cache = new DecryptedCapsaCache();
      const fullFile = createTestFile('file-1', {
        iv: 'test-iv',
        authTag: 'test-auth-tag',
        compressed: true,
        encryptedFilename: 'encrypted-name',
        filenameIV: 'fn-iv',
        filenameAuthTag: 'fn-auth-tag',
      });

      cache.set('capsa-1', Buffer.from('key'), [fullFile]);

      const metadata = cache.getFileMetadata('capsa-1', 'file-1');
      expect(metadata).toEqual({
        iv: 'test-iv',
        authTag: 'test-auth-tag',
        compressed: true,
        encryptedFilename: 'encrypted-name',
        filenameIV: 'fn-iv',
        filenameAuthTag: 'fn-auth-tag',
      });
    });
  });

  describe('has() Method', () => {
    it('should return true for cached capsa', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key'), []);

      expect(cache.has('capsa-1')).toBe(true);
    });

    it('should return false for non-existent capsaId', () => {
      const cache = new DecryptedCapsaCache();
      expect(cache.has('non-existent')).toBe(false);
    });

    it('should return false for expired entry', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1000 });
      cache.set('capsa-1', Buffer.from('key'), []);

      expect(cache.has('capsa-1')).toBe(true);

      vi.advanceTimersByTime(1001);

      expect(cache.has('capsa-1')).toBe(false);
    });

    it('should return true for entry at exactly expiry time', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1000 });
      cache.set('capsa-1', Buffer.from('key'), []);

      vi.advanceTimersByTime(1000);

      expect(cache.has('capsa-1')).toBe(true);
    });

    it('should trigger deletion of expired entry', () => {
      const cache = new DecryptedCapsaCache({ ttl: 500 });
      cache.set('capsa-1', Buffer.from('key'), []);
      cache.set('capsa-2', Buffer.from('key'), []);

      expect(cache.size).toBe(2);

      vi.advanceTimersByTime(501);

      cache.has('capsa-1'); // Should delete expired entry
      expect(cache.size).toBe(1);
    });
  });

  describe('clear() Method', () => {
    it('should remove specific capsa from cache', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key-1'), []);
      cache.set('capsa-2', Buffer.from('key-2'), []);

      cache.clear('capsa-1');

      expect(cache.has('capsa-1')).toBe(false);
      expect(cache.has('capsa-2')).toBe(true);
      expect(cache.size).toBe(1);
    });

    it('should not throw when clearing non-existent capsaId', () => {
      const cache = new DecryptedCapsaCache();
      expect(() => cache.clear('non-existent')).not.toThrow();
    });

    it('should handle clearing already cleared capsa', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key'), []);
      cache.clear('capsa-1');
      cache.clear('capsa-1');

      expect(cache.size).toBe(0);
    });

    it('should only affect specified capsaId', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key-1'), [createTestFile('file-1')]);
      cache.set('capsa-2', Buffer.from('key-2'), [createTestFile('file-2')]);
      cache.set('capsa-3', Buffer.from('key-3'), [createTestFile('file-3')]);

      cache.clear('capsa-2');

      expect(cache.size).toBe(2);
      expect(cache.getMasterKey('capsa-1')).toEqual(Buffer.from('key-1'));
      expect(cache.getMasterKey('capsa-2')).toBeNull();
      expect(cache.getMasterKey('capsa-3')).toEqual(Buffer.from('key-3'));
    });
  });

  describe('clearAll() Method', () => {
    it('should remove all entries from cache', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key-1'), []);
      cache.set('capsa-2', Buffer.from('key-2'), []);
      cache.set('capsa-3', Buffer.from('key-3'), []);

      expect(cache.size).toBe(3);

      cache.clearAll();

      expect(cache.size).toBe(0);
      expect(cache.has('capsa-1')).toBe(false);
      expect(cache.has('capsa-2')).toBe(false);
      expect(cache.has('capsa-3')).toBe(false);
    });

    it('should not throw when cache is already empty', () => {
      const cache = new DecryptedCapsaCache();
      expect(() => cache.clearAll()).not.toThrow();
      expect(cache.size).toBe(0);
    });

    it('should allow adding new entries after clearAll', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key-1'), []);
      cache.clearAll();

      cache.set('capsa-2', Buffer.from('key-2'), []);
      expect(cache.size).toBe(1);
      expect(cache.has('capsa-2')).toBe(true);
    });
  });

  describe('clearMasterKey() Method', () => {
    it('should remove entire entry (including files)', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key-1'), [createTestFile('file-1')]);

      cache.clearMasterKey('capsa-1');

      expect(cache.has('capsa-1')).toBe(false);
      expect(cache.getMasterKey('capsa-1')).toBeNull();
      expect(cache.getFileMetadata('capsa-1', 'file-1')).toBeNull();
      expect(cache.size).toBe(0);
    });

    it('should not throw when clearing non-existent capsaId', () => {
      const cache = new DecryptedCapsaCache();
      expect(() => cache.clearMasterKey('non-existent')).not.toThrow();
    });

    it('should only affect specified capsaId', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key-1'), []);
      cache.set('capsa-2', Buffer.from('key-2'), []);

      cache.clearMasterKey('capsa-1');

      expect(cache.has('capsa-1')).toBe(false);
      expect(cache.has('capsa-2')).toBe(true);
    });
  });

  describe('size Getter', () => {
    it('should return 0 for empty cache', () => {
      const cache = new DecryptedCapsaCache();
      expect(cache.size).toBe(0);
    });

    it('should return correct count after adding entries', () => {
      const cache = new DecryptedCapsaCache();

      cache.set('capsa-1', Buffer.from('key-1'), []);
      expect(cache.size).toBe(1);

      cache.set('capsa-2', Buffer.from('key-2'), []);
      expect(cache.size).toBe(2);

      cache.set('capsa-3', Buffer.from('key-3'), []);
      expect(cache.size).toBe(3);
    });

    it('should not increase when overwriting existing entry', () => {
      const cache = new DecryptedCapsaCache();

      cache.set('capsa-1', Buffer.from('key-1'), []);
      expect(cache.size).toBe(1);

      cache.set('capsa-1', Buffer.from('key-2'), []);
      expect(cache.size).toBe(1);
    });

    it('should decrease when entries are cleared', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key-1'), []);
      cache.set('capsa-2', Buffer.from('key-2'), []);

      cache.clear('capsa-1');
      expect(cache.size).toBe(1);

      cache.clear('capsa-2');
      expect(cache.size).toBe(0);
    });

    it('should return 0 after clearAll', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key-1'), []);
      cache.set('capsa-2', Buffer.from('key-2'), []);
      cache.set('capsa-3', Buffer.from('key-3'), []);

      cache.clearAll();
      expect(cache.size).toBe(0);
    });

    it('should not include expired entries in count until accessed', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1000 });
      cache.set('capsa-1', Buffer.from('key-1'), []);
      cache.set('capsa-2', Buffer.from('key-2'), []);

      vi.advanceTimersByTime(1001);

      // Size still shows 2 because expired entries are not automatically pruned
      expect(cache.size).toBe(2);

      // Accessing triggers deletion
      cache.get('capsa-1');
      expect(cache.size).toBe(1);
    });
  });

  describe('prune() Method', () => {
    it('should remove all expired entries', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1000 });
      cache.set('capsa-1', Buffer.from('key-1'), []);
      cache.set('capsa-2', Buffer.from('key-2'), []);
      cache.set('capsa-3', Buffer.from('key-3'), []);

      vi.advanceTimersByTime(1001);

      expect(cache.size).toBe(3);

      cache.prune();

      expect(cache.size).toBe(0);
    });

    it('should keep non-expired entries', () => {
      const cache = new DecryptedCapsaCache({ ttl: 2000 });

      cache.set('capsa-old', Buffer.from('key-old'), []);
      vi.advanceTimersByTime(1500);
      cache.set('capsa-new', Buffer.from('key-new'), []);
      vi.advanceTimersByTime(600);

      // capsa-old is now expired (1500 + 600 = 2100 > 2000)
      // capsa-new is not expired (600 < 2000)
      cache.prune();

      expect(cache.size).toBe(1);
      expect(cache.has('capsa-old')).toBe(false);
      expect(cache.has('capsa-new')).toBe(true);
    });

    it('should not throw on empty cache', () => {
      const cache = new DecryptedCapsaCache();
      expect(() => cache.prune()).not.toThrow();
    });

    it('should handle all entries expired', () => {
      const cache = new DecryptedCapsaCache({ ttl: 500 });
      for (let i = 0; i < 10; i++) {
        cache.set(`capsa-${i}`, Buffer.from(`key-${i}`), []);
      }

      vi.advanceTimersByTime(501);
      cache.prune();

      expect(cache.size).toBe(0);
    });

    it('should handle no entries expired', () => {
      const cache = new DecryptedCapsaCache({ ttl: 10000 });
      cache.set('capsa-1', Buffer.from('key-1'), []);
      cache.set('capsa-2', Buffer.from('key-2'), []);

      vi.advanceTimersByTime(1000);
      cache.prune();

      expect(cache.size).toBe(2);
    });

    it('should handle entries expiring exactly at prune time', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1000 });
      cache.set('capsa-1', Buffer.from('key-1'), []);

      vi.advanceTimersByTime(1000);
      cache.prune();

      // Entry with expiresAt === now should NOT be pruned (condition is > not >=)
      expect(cache.size).toBe(1);
    });

    it('should handle mixed expiration states', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1000 });

      cache.set('capsa-1', Buffer.from('key-1'), []);
      vi.advanceTimersByTime(600);
      cache.set('capsa-2', Buffer.from('key-2'), []);
      vi.advanceTimersByTime(600);
      cache.set('capsa-3', Buffer.from('key-3'), []);
      vi.advanceTimersByTime(600);

      // Now at t=1800:
      // capsa-1: cachedAt=0, expiresAt=1000, elapsed=1800 > 1000 (expired)
      // capsa-2: cachedAt=600, expiresAt=1600, elapsed=1200 > 1000 (expired)
      // capsa-3: cachedAt=1200, expiresAt=2200, elapsed=600 < 1000 (not expired)
      cache.prune();

      expect(cache.size).toBe(1);
      expect(cache.has('capsa-3')).toBe(true);
    });
  });

  describe('TTL Expiration Behavior', () => {
    it('should use default TTL of 5 minutes', () => {
      const cache = new DecryptedCapsaCache();
      cache.set('capsa-1', Buffer.from('key'), []);

      // Just before 5 minutes
      vi.advanceTimersByTime(299999);
      expect(cache.has('capsa-1')).toBe(true);

      // After 5 minutes
      vi.advanceTimersByTime(2);
      expect(cache.has('capsa-1')).toBe(false);
    });

    it('should correctly handle very short TTL', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1 });
      cache.set('capsa-1', Buffer.from('key'), []);

      expect(cache.has('capsa-1')).toBe(true);

      vi.advanceTimersByTime(2);
      expect(cache.has('capsa-1')).toBe(false);
    });

    it('should correctly handle very long TTL', () => {
      const cache = new DecryptedCapsaCache({ ttl: 86400000 }); // 24 hours
      cache.set('capsa-1', Buffer.from('key'), []);

      vi.advanceTimersByTime(43200000); // 12 hours
      expect(cache.has('capsa-1')).toBe(true);

      vi.advanceTimersByTime(43200001); // Past 24 hours
      expect(cache.has('capsa-1')).toBe(false);
    });

    it('should update expiresAt when entry is overwritten', () => {
      const cache = new DecryptedCapsaCache({ ttl: 1000 });
      cache.set('capsa-1', Buffer.from('key-1'), []);

      vi.advanceTimersByTime(800);

      // Overwrite resets the TTL
      cache.set('capsa-1', Buffer.from('key-2'), []);

      vi.advanceTimersByTime(800);
      expect(cache.has('capsa-1')).toBe(true);

      vi.advanceTimersByTime(201);
      expect(cache.has('capsa-1')).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle capsaId with special characters', () => {
      const cache = new DecryptedCapsaCache();
      const specialId = 'capsa-123_abc-DEF.xyz';

      cache.set(specialId, Buffer.from('key'), []);
      expect(cache.has(specialId)).toBe(true);
      expect(cache.getMasterKey(specialId)).toEqual(Buffer.from('key'));
    });

    it('should handle empty string capsaId', () => {
      const cache = new DecryptedCapsaCache();

      cache.set('', Buffer.from('key'), []);
      expect(cache.has('')).toBe(true);
      expect(cache.getMasterKey('')).toEqual(Buffer.from('key'));
    });

    it('should handle fileId with special characters', () => {
      const cache = new DecryptedCapsaCache();
      const specialFileId = 'file_123-abc.pdf';

      cache.set('capsa-1', Buffer.from('key'), [createTestFile(specialFileId)]);
      expect(cache.getFileMetadata('capsa-1', specialFileId)).not.toBeNull();
    });

    it('should handle very long master key buffers', () => {
      const cache = new DecryptedCapsaCache();
      const longKey = Buffer.from('a'.repeat(10000));

      cache.set('capsa-1', longKey, []);
      expect(cache.getMasterKey('capsa-1')).toEqual(longKey);
    });

    it('should handle many files in single capsa', () => {
      const cache = new DecryptedCapsaCache();
      const files = Array.from({ length: 100 }, (_, i) =>
        createTestFile(`file-${i}`, { iv: `iv-${i}` })
      );

      cache.set('capsa-1', Buffer.from('key'), files);

      const entry = cache.get('capsa-1');
      expect(entry!.files.size).toBe(100);
      expect(cache.getFileMetadata('capsa-1', 'file-50')!.iv).toBe('iv-50');
    });

    it('should handle maxSize of 1', () => {
      const cache = new DecryptedCapsaCache({ maxSize: 1 });

      cache.set('capsa-1', Buffer.from('key-1'), []);
      expect(cache.size).toBe(1);

      cache.set('capsa-2', Buffer.from('key-2'), []);
      expect(cache.size).toBe(1);
      expect(cache.has('capsa-1')).toBe(false);
      expect(cache.has('capsa-2')).toBe(true);
    });

    it('should handle TTL of 0', () => {
      const cache = new DecryptedCapsaCache({ ttl: 0 });

      cache.set('capsa-1', Buffer.from('key'), []);

      // With TTL of 0, expiresAt equals cachedAt (now)
      // Since condition is > not >=, entry should still be valid at same time
      expect(cache.has('capsa-1')).toBe(true);

      // One millisecond later, it expires
      vi.advanceTimersByTime(1);
      expect(cache.has('capsa-1')).toBe(false);
    });

    it('should handle duplicate fileIds in set (last one wins)', () => {
      const cache = new DecryptedCapsaCache();
      const files = [
        createTestFile('file-1', { iv: 'first-iv' }),
        createTestFile('file-1', { iv: 'second-iv' }),
      ];

      cache.set('capsa-1', Buffer.from('key'), files);

      const metadata = cache.getFileMetadata('capsa-1', 'file-1');
      expect(metadata!.iv).toBe('second-iv');
    });

    it('should maintain separate file maps for different capsas', () => {
      const cache = new DecryptedCapsaCache();

      cache.set('capsa-1', Buffer.from('key-1'), [createTestFile('shared-file-id', { iv: 'iv-from-capsa-1' })]);
      cache.set('capsa-2', Buffer.from('key-2'), [createTestFile('shared-file-id', { iv: 'iv-from-capsa-2' })]);

      expect(cache.getFileMetadata('capsa-1', 'shared-file-id')!.iv).toBe('iv-from-capsa-1');
      expect(cache.getFileMetadata('capsa-2', 'shared-file-id')!.iv).toBe('iv-from-capsa-2');
    });
  });

  describe('Concurrency Simulation', () => {
    it('should handle rapid sequential set/get operations', () => {
      const cache = new DecryptedCapsaCache();

      for (let i = 0; i < 100; i++) {
        cache.set(`capsa-${i}`, Buffer.from(`key-${i}`), [createTestFile(`file-${i}`)]);
        expect(cache.getMasterKey(`capsa-${i}`)).toEqual(Buffer.from(`key-${i}`));
      }

      expect(cache.size).toBe(100);
    });

    it('should handle interleaved operations', () => {
      const cache = new DecryptedCapsaCache({ maxSize: 50 });

      for (let i = 0; i < 100; i++) {
        cache.set(`capsa-${i}`, Buffer.from(`key-${i}`), []);

        if (i % 3 === 0) {
          cache.clear(`capsa-${i}`);
        }
      }

      // Some entries cleared, some evicted, should have consistent state
      expect(cache.size).toBeLessThanOrEqual(50);
    });
  });
});

describe('createCapsaCache Factory Function', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should return a DecryptedCapsaCache instance', () => {
    const cache = createCapsaCache();
    expect(cache).toBeInstanceOf(DecryptedCapsaCache);
  });

  it('should create cache with default config when no config provided', () => {
    const cache = createCapsaCache();

    cache.set('capsa-1', Buffer.from('key'), []);

    // Default TTL is 5 minutes
    vi.advanceTimersByTime(299999);
    expect(cache.has('capsa-1')).toBe(true);

    vi.advanceTimersByTime(2);
    expect(cache.has('capsa-1')).toBe(false);
  });

  it('should create cache with default config when undefined provided', () => {
    const cache = createCapsaCache(undefined);
    expect(cache).toBeInstanceOf(DecryptedCapsaCache);
  });

  it('should create cache with custom TTL', () => {
    const cache = createCapsaCache({ ttl: 1000 });

    cache.set('capsa-1', Buffer.from('key'), []);

    vi.advanceTimersByTime(1001);
    expect(cache.has('capsa-1')).toBe(false);
  });

  it('should create cache with custom maxSize', () => {
    const cache = createCapsaCache({ maxSize: 2 });

    cache.set('capsa-1', Buffer.from('key-1'), []);
    cache.set('capsa-2', Buffer.from('key-2'), []);
    cache.set('capsa-3', Buffer.from('key-3'), []);

    expect(cache.size).toBe(2);
  });

  it('should create cache with both custom TTL and maxSize', () => {
    const cache = createCapsaCache({ ttl: 500, maxSize: 5 });

    cache.set('capsa-1', Buffer.from('key'), []);
    vi.advanceTimersByTime(501);

    expect(cache.has('capsa-1')).toBe(false);
  });

  it('should create independent cache instances', () => {
    const cache1 = createCapsaCache();
    const cache2 = createCapsaCache();

    cache1.set('capsa-1', Buffer.from('key-from-cache1'), []);

    expect(cache1.has('capsa-1')).toBe(true);
    expect(cache2.has('capsa-1')).toBe(false);
  });

  it('should allow different configs for different instances', () => {
    const shortTtlCache = createCapsaCache({ ttl: 100 });
    const longTtlCache = createCapsaCache({ ttl: 10000 });

    shortTtlCache.set('capsa-1', Buffer.from('key'), []);
    longTtlCache.set('capsa-1', Buffer.from('key'), []);

    vi.advanceTimersByTime(101);

    expect(shortTtlCache.has('capsa-1')).toBe(false);
    expect(longTtlCache.has('capsa-1')).toBe(true);
  });
});

describe('Type Exports', () => {
  it('should export CachedFileMetadata interface', () => {
    const metadata: CachedFileMetadata = {
      iv: 'test-iv',
      authTag: 'test-auth-tag',
      encryptedFilename: 'encrypted',
      filenameIV: 'fn-iv',
      filenameAuthTag: 'fn-auth-tag',
    };

    expect(metadata.iv).toBe('test-iv');
  });

  it('should export CachedCapsa interface', () => {
    const cachedCapsa: CachedCapsa = {
      masterKey: Buffer.from('test-key'),
      files: new Map(),
      cachedAt: Date.now(),
      expiresAt: Date.now() + 1000,
    };

    expect(cachedCapsa.masterKey).toEqual(Buffer.from('test-key'));
  });

  it('should export CapsaCacheConfig interface', () => {
    const config: CapsaCacheConfig = {
      ttl: 1000,
      maxSize: 50,
    };

    expect(config.ttl).toBe(1000);
  });

  it('should allow partial CapsaCacheConfig', () => {
    const ttlOnly: CapsaCacheConfig = { ttl: 500 };
    const maxSizeOnly: CapsaCacheConfig = { maxSize: 10 };
    const empty: CapsaCacheConfig = {};

    expect(ttlOnly.ttl).toBe(500);
    expect(maxSizeOnly.maxSize).toBe(10);
    expect(empty).toEqual({});
  });

  it('should allow optional compressed field in CachedFileMetadata', () => {
    const withCompressed: CachedFileMetadata = {
      iv: 'iv',
      authTag: 'auth',
      compressed: true,
      encryptedFilename: 'name',
      filenameIV: 'fiv',
      filenameAuthTag: 'fauth',
    };

    const withoutCompressed: CachedFileMetadata = {
      iv: 'iv',
      authTag: 'auth',
      encryptedFilename: 'name',
      filenameIV: 'fiv',
      filenameAuthTag: 'fauth',
    };

    expect(withCompressed.compressed).toBe(true);
    expect(withoutCompressed.compressed).toBeUndefined();
  });
});
