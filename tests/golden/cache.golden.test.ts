/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - DecryptedCapsaCache
 * Tests set/get, TTL expiry, max size eviction, clear specific/all,
 * has valid/expired, prune, file metadata lookup, cleared on logout pattern.
 */

import { DecryptedCapsaCache, type CachedFileMetadata } from '../../src/internal/capsa-cache.js';

function createFileEntry(fileId: string): { fileId: string } & CachedFileMetadata {
  return {
    fileId,
    iv: `iv_${fileId}`,
    authTag: `tag_${fileId}`,
    encryptedFilename: `enc_${fileId}`,
    filenameIV: `fniv_${fileId}`,
    filenameAuthTag: `fntag_${fileId}`,
  };
}

describe('Golden: Cache', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should set and get cached capsa', () => {
    const cache = new DecryptedCapsaCache();
    cache.set('capsa_1', Buffer.from('masterkey_base64'), [createFileEntry('file_1.enc')]);

    const entry = cache.get('capsa_1');

    expect(entry).not.toBeNull();
    expect(entry!.masterKey.toString()).toBe('masterkey_base64');
    expect(entry!.files.size).toBe(1);
  });

  it('should return null for expired entries (TTL)', () => {
    const cache = new DecryptedCapsaCache({ ttl: 1000 }); // 1 second TTL
    cache.set('capsa_1', Buffer.from('key'), [createFileEntry('f.enc')]);

    // Before TTL
    expect(cache.get('capsa_1')).not.toBeNull();

    // After TTL
    vi.advanceTimersByTime(1500);
    expect(cache.get('capsa_1')).toBeNull();
  });

  it('should evict oldest entry when max size exceeded', () => {
    const cache = new DecryptedCapsaCache({ maxSize: 2 });

    // Set current time baseline
    vi.setSystemTime(new Date('2025-01-01T00:00:00Z'));
    cache.set('capsa_oldest', Buffer.from('key1'), [createFileEntry('f1.enc')]);

    vi.advanceTimersByTime(100);
    cache.set('capsa_newer', Buffer.from('key2'), [createFileEntry('f2.enc')]);

    vi.advanceTimersByTime(100);
    // This should evict capsa_oldest
    cache.set('capsa_newest', Buffer.from('key3'), [createFileEntry('f3.enc')]);

    expect(cache.get('capsa_oldest')).toBeNull();
    expect(cache.get('capsa_newer')).not.toBeNull();
    expect(cache.get('capsa_newest')).not.toBeNull();
    expect(cache.size).toBe(2);
  });

  it('should clear a specific capsa from cache', () => {
    const cache = new DecryptedCapsaCache();
    cache.set('capsa_1', Buffer.from('key1'), [createFileEntry('f1.enc')]);
    cache.set('capsa_2', Buffer.from('key2'), [createFileEntry('f2.enc')]);

    cache.clear('capsa_1');

    expect(cache.get('capsa_1')).toBeNull();
    expect(cache.get('capsa_2')).not.toBeNull();
  });

  it('should clear all cached data', () => {
    const cache = new DecryptedCapsaCache();
    cache.set('capsa_1', Buffer.from('key1'), [createFileEntry('f1.enc')]);
    cache.set('capsa_2', Buffer.from('key2'), [createFileEntry('f2.enc')]);

    cache.clearAll();

    expect(cache.size).toBe(0);
    expect(cache.get('capsa_1')).toBeNull();
    expect(cache.get('capsa_2')).toBeNull();
  });

  it('should report has() correctly for valid and expired entries', () => {
    const cache = new DecryptedCapsaCache({ ttl: 500 });
    cache.set('capsa_1', Buffer.from('key'), [createFileEntry('f.enc')]);

    expect(cache.has('capsa_1')).toBe(true);
    expect(cache.has('capsa_nonexistent')).toBe(false);

    vi.advanceTimersByTime(600);
    expect(cache.has('capsa_1')).toBe(false);
  });

  it('should prune expired entries', () => {
    const cache = new DecryptedCapsaCache({ ttl: 500 });

    vi.setSystemTime(new Date('2025-01-01T00:00:00Z'));
    cache.set('capsa_old', Buffer.from('key1'), [createFileEntry('f1.enc')]);

    vi.advanceTimersByTime(600); // This entry is now expired
    cache.set('capsa_new', Buffer.from('key2'), [createFileEntry('f2.enc')]);

    expect(cache.size).toBe(2); // Both still in Map

    cache.prune();

    expect(cache.size).toBe(1);
    expect(cache.get('capsa_old')).toBeNull();
    expect(cache.get('capsa_new')).not.toBeNull();
  });

  it('should look up file metadata by capsaId and fileId', () => {
    const cache = new DecryptedCapsaCache();
    cache.set('capsa_1', Buffer.from('key'), [
      createFileEntry('file_a.enc'),
      createFileEntry('file_b.enc'),
    ]);

    const meta = cache.getFileMetadata('capsa_1', 'file_b.enc');

    expect(meta).not.toBeNull();
    expect(meta!.iv).toBe('iv_file_b.enc');
    expect(meta!.authTag).toBe('tag_file_b.enc');
  });

  it('should return null for file metadata from non-existent capsa', () => {
    const cache = new DecryptedCapsaCache();
    const meta = cache.getFileMetadata('nonexistent', 'file.enc');

    expect(meta).toBeNull();
  });

  it('should support clearAll as logout pattern (cache cleared on logout)', () => {
    const cache = new DecryptedCapsaCache();
    cache.set('capsa_1', Buffer.from('key1'), [createFileEntry('f1.enc')]);
    cache.set('capsa_2', Buffer.from('key2'), [createFileEntry('f2.enc')]);
    cache.set('capsa_3', Buffer.from('key3'), [createFileEntry('f3.enc')]);

    // Simulate logout by clearing everything
    cache.clearAll();

    expect(cache.size).toBe(0);
    expect(cache.getMasterKey('capsa_1')).toBeNull();
    expect(cache.getMasterKey('capsa_2')).toBeNull();
    expect(cache.getMasterKey('capsa_3')).toBeNull();
  });
});
