/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Compression
 * Tests roundtrip, threshold (below/at/above 150B), invalid data,
 * metadata tracking. Uses real compression functions.
 */

import { compressData, decompressData, shouldCompress } from '../../src/internal/crypto/compression.js';

describe('Golden: Compression', () => {
  it('should roundtrip compress/decompress', async () => {
    const original = Buffer.from('Hello, this is test data for compression roundtrip validation!');
    const compressed = await compressData(original);
    const decompressed = await decompressData(compressed.compressedData);

    expect(decompressed.equals(original)).toBe(true);
  });

  it('should not recommend compression below 150 bytes', () => {
    expect(shouldCompress(0)).toBe(false);
    expect(shouldCompress(1)).toBe(false);
    expect(shouldCompress(100)).toBe(false);
    expect(shouldCompress(149)).toBe(false);
  });

  it('should recommend compression at exactly 150 bytes', () => {
    expect(shouldCompress(150)).toBe(true);
  });

  it('should recommend compression above 150 bytes', () => {
    expect(shouldCompress(151)).toBe(true);
    expect(shouldCompress(1024)).toBe(true);
    expect(shouldCompress(1024 * 1024)).toBe(true);
  });

  it('should throw on invalid compressed data', async () => {
    const invalidData = Buffer.from('this is not valid gzip data');

    await expect(decompressData(invalidData)).rejects.toThrow(/Failed to decompress/);
  });

  it('should track compression metadata (originalSize, compressedSize)', async () => {
    // Use repetitive data that compresses well
    const original = Buffer.from('a'.repeat(1000));
    const result = await compressData(original);

    expect(result.originalSize).toBe(1000);
    expect(result.compressedSize).toBe(result.compressedData.length);
    // Repetitive data should compress significantly
    expect(result.compressedSize).toBeLessThan(result.originalSize);
    // Compressed data should be a Buffer
    expect(Buffer.isBuffer(result.compressedData)).toBe(true);
  });
});
