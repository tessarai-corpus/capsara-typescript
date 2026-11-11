/// <reference types="vitest/globals" />
/**
 * Tests for compression utilities
 * @module tests/unit/internal/crypto/compression.test
 *
 * Tests gzip compression/decompression operations with full branch coverage
 * including edge cases, error handling, and round-trip validation.
 */

import * as crypto from 'crypto';
import * as zlib from 'zlib';
import { promisify } from 'util';
import {
  compressData,
  decompressData,
  shouldCompress,
  type CompressionResult,
} from '../../../../src/internal/crypto/compression.js';

const gzipAsync = promisify(zlib.gzip);

describe('compressData', () => {
  describe('Output Structure', () => {
    it('should return a CompressionResult object with all required properties', async () => {
      const data = Buffer.from('test data for compression');
      const result = await compressData(data);

      expect(result).toHaveProperty('compressedData');
      expect(result).toHaveProperty('originalSize');
      expect(result).toHaveProperty('compressedSize');
    });

    it('should return compressedData as a Buffer', async () => {
      const data = Buffer.from('test data');
      const result = await compressData(data);

      expect(Buffer.isBuffer(result.compressedData)).toBe(true);
    });

    it('should return originalSize matching input buffer length', async () => {
      const data = Buffer.from('test data for size verification');
      const result = await compressData(data);

      expect(result.originalSize).toBe(data.length);
    });

    it('should return compressedSize matching compressed buffer length', async () => {
      const data = Buffer.from('test data for compressed size verification');
      const result = await compressData(data);

      expect(result.compressedSize).toBe(result.compressedData.length);
    });
  });

  describe('Compression Output Validity', () => {
    it('should produce valid gzip output that can be decompressed by Node.js zlib', async () => {
      const data = Buffer.from('data that should be valid gzip');
      const result = await compressData(data);

      // Verify it's valid gzip by decompressing with native zlib
      const gunzipAsync = promisify(zlib.gunzip);
      const decompressed = await gunzipAsync(result.compressedData);

      expect(decompressed.equals(data)).toBe(true);
    });

    it('should produce output starting with gzip magic bytes (0x1f 0x8b)', async () => {
      const data = Buffer.from('data for magic byte verification');
      const result = await compressData(data);

      // Gzip magic number: 0x1f 0x8b
      expect(result.compressedData[0]).toBe(0x1f);
      expect(result.compressedData[1]).toBe(0x8b);
    });

    it('should compress identical data to same output (deterministic compression)', async () => {
      const data = Buffer.from('identical data for determinism test');
      const result1 = await compressData(data);
      const result2 = await compressData(data);

      // gzip with same settings should produce identical output
      expect(result1.compressedData.equals(result2.compressedData)).toBe(true);
    });
  });

  describe('Compression Effectiveness', () => {
    it('should reduce size for highly repetitive text data', async () => {
      // Highly compressible: repeating pattern
      const repetitiveData = Buffer.from('AAAAAAAAAA'.repeat(100));
      const result = await compressData(repetitiveData);

      expect(result.compressedSize).toBeLessThan(result.originalSize);
    });

    it('should reduce size for plain English text', async () => {
      const textData = Buffer.from(
        'The quick brown fox jumps over the lazy dog. ' +
          'This is a common English sentence used for typing practice. ' +
          'It contains all letters of the alphabet and demonstrates typical ' +
          'compression ratios for natural language text content.'
      );
      const result = await compressData(textData);

      expect(result.compressedSize).toBeLessThan(result.originalSize);
    });

    it('should reduce size for JSON data with repeated keys', async () => {
      const jsonData = Buffer.from(
        JSON.stringify(
          Array(50)
            .fill(null)
            .map((_, i) => ({
              id: i,
              name: 'user',
              email: 'test@example.com',
              active: true,
            }))
        )
      );
      const result = await compressData(jsonData);

      expect(result.compressedSize).toBeLessThan(result.originalSize);
    });

    it('should not significantly reduce size for random binary data', async () => {
      // Random data is incompressible
      const randomData = crypto.randomBytes(1000);
      const result = await compressData(randomData);

      // Random data typically expands slightly or stays same (gzip header overhead)
      // Allow up to 10% expansion for the header
      expect(result.compressedSize).toBeLessThanOrEqual(result.originalSize * 1.1);
    });

    it('should handle already-compressed data without crashing', async () => {
      // Compress data, then compress again (nested compression)
      const originalData = Buffer.from('test data');
      const firstCompress = await compressData(originalData);
      const secondCompress = await compressData(firstCompress.compressedData);

      // Should complete without error
      expect(secondCompress.compressedData).toBeDefined();
      expect(secondCompress.originalSize).toBe(firstCompress.compressedSize);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty buffer', async () => {
      const emptyData = Buffer.from('');
      const result = await compressData(emptyData);

      expect(result.originalSize).toBe(0);
      expect(result.compressedData).toBeDefined();
      // Compressed size will be > 0 due to gzip header
      expect(result.compressedSize).toBeGreaterThan(0);
    });

    it('should handle single byte buffer', async () => {
      const singleByte = Buffer.from([0x42]);
      const result = await compressData(singleByte);

      expect(result.originalSize).toBe(1);
      expect(result.compressedData).toBeDefined();
    });

    it('should handle buffer with all zero bytes', async () => {
      const zeroes = Buffer.alloc(1000, 0);
      const result = await compressData(zeroes);

      expect(result.originalSize).toBe(1000);
      // All-zero data compresses very well
      expect(result.compressedSize).toBeLessThan(result.originalSize);
    });

    it('should handle buffer with all possible byte values', async () => {
      const allBytes = Buffer.alloc(256);
      for (let i = 0; i < 256; i++) {
        allBytes[i] = i;
      }
      const result = await compressData(allBytes);

      expect(result.originalSize).toBe(256);
      expect(result.compressedData).toBeDefined();
    });

    it('should handle large data (1MB)', async () => {
      const largeData = crypto.randomBytes(1024 * 1024);
      const result = await compressData(largeData);

      expect(result.originalSize).toBe(1024 * 1024);
      expect(result.compressedData).toBeDefined();
    });

    it('should handle UTF-8 text with multibyte characters', async () => {
      const unicodeText = Buffer.from(
        'Unicode test: \u4E2D\u6587 \u65E5\u672C\u8A9E \uD83D\uDE00 \u00E9\u00E8\u00EA \u0411\u0443\u043A\u0432\u0430'
      );
      const result = await compressData(unicodeText);

      expect(result.originalSize).toBe(unicodeText.length);
      expect(result.compressedData).toBeDefined();
    });

    it('should handle buffer containing null bytes interspersed with data', async () => {
      const mixedData = Buffer.from([
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x00, 0x00, 0x57, 0x6f, 0x72, 0x6c, 0x64,
      ]);
      const result = await compressData(mixedData);

      expect(result.originalSize).toBe(13);
      expect(result.compressedData).toBeDefined();
    });
  });

  describe('Consistency', () => {
    it('should return consistent results across multiple compressions', async () => {
      const data = Buffer.from('consistency test data');
      const results: CompressionResult[] = [];

      for (let i = 0; i < 10; i++) {
        results.push(await compressData(data));
      }

      // All results should have same values
      const firstResult = results[0]!;
      for (const result of results) {
        expect(result.originalSize).toBe(firstResult.originalSize);
        expect(result.compressedSize).toBe(firstResult.compressedSize);
        expect(result.compressedData.equals(firstResult.compressedData)).toBe(true);
      }
    });
  });
});

describe('decompressData', () => {
  describe('Successful Decompression', () => {
    it('should decompress valid gzip data to original content', async () => {
      const originalData = Buffer.from('test data for decompression');
      const compressed = await gzipAsync(originalData);
      const decompressed = await decompressData(compressed);

      expect(decompressed.equals(originalData)).toBe(true);
    });

    it('should return a Buffer', async () => {
      const originalData = Buffer.from('buffer type test');
      const compressed = await gzipAsync(originalData);
      const decompressed = await decompressData(compressed);

      expect(Buffer.isBuffer(decompressed)).toBe(true);
    });

    it('should decompress empty gzip stream correctly', async () => {
      const emptyData = Buffer.from('');
      const compressed = await gzipAsync(emptyData);
      const decompressed = await decompressData(compressed);

      expect(decompressed.length).toBe(0);
      expect(decompressed.equals(emptyData)).toBe(true);
    });

    it('should decompress large data correctly', async () => {
      const largeData = crypto.randomBytes(100 * 1024); // 100 KB
      const compressed = await gzipAsync(largeData);
      const decompressed = await decompressData(compressed);

      expect(decompressed.equals(largeData)).toBe(true);
    });

    it('should decompress UTF-8 text with special characters correctly', async () => {
      const unicodeText = Buffer.from('Unicode: \uD83D\uDE00 \u4E2D\u6587 \u00E9\u00E8\u00EA');
      const compressed = await gzipAsync(unicodeText);
      const decompressed = await decompressData(compressed);

      expect(decompressed.toString('utf-8')).toBe(unicodeText.toString('utf-8'));
    });

    it('should decompress binary data with all byte values correctly', async () => {
      const binaryData = Buffer.alloc(256);
      for (let i = 0; i < 256; i++) {
        binaryData[i] = i;
      }
      const compressed = await gzipAsync(binaryData);
      const decompressed = await decompressData(compressed);

      expect(decompressed.equals(binaryData)).toBe(true);
    });
  });

  describe('Round-Trip Compression', () => {
    it('should round-trip simple text data', async () => {
      const originalData = Buffer.from('Hello, World!');
      const compressed = await compressData(originalData);
      const decompressed = await decompressData(compressed.compressedData);

      expect(decompressed.equals(originalData)).toBe(true);
    });

    it('should round-trip empty buffer', async () => {
      const originalData = Buffer.from('');
      const compressed = await compressData(originalData);
      const decompressed = await decompressData(compressed.compressedData);

      expect(decompressed.equals(originalData)).toBe(true);
    });

    it('should round-trip single byte', async () => {
      const originalData = Buffer.from([0xff]);
      const compressed = await compressData(originalData);
      const decompressed = await decompressData(compressed.compressedData);

      expect(decompressed.equals(originalData)).toBe(true);
    });

    it('should round-trip random binary data', async () => {
      const originalData = crypto.randomBytes(10000);
      const compressed = await compressData(originalData);
      const decompressed = await decompressData(compressed.compressedData);

      expect(decompressed.equals(originalData)).toBe(true);
    });

    it('should round-trip highly compressible data', async () => {
      const originalData = Buffer.from('A'.repeat(10000));
      const compressed = await compressData(originalData);
      const decompressed = await decompressData(compressed.compressedData);

      expect(decompressed.equals(originalData)).toBe(true);
    });

    it('should round-trip JSON data', async () => {
      const jsonObject = {
        id: 12345,
        name: 'Test User',
        email: 'user@example.com',
        nested: { key: 'value', array: [1, 2, 3] },
      };
      const originalData = Buffer.from(JSON.stringify(jsonObject));
      const compressed = await compressData(originalData);
      const decompressed = await decompressData(compressed.compressedData);

      expect(JSON.parse(decompressed.toString('utf-8'))).toEqual(jsonObject);
    });

    it('should round-trip multiple different data types', async () => {
      const testCases = [
        Buffer.from(''),
        Buffer.from('a'),
        Buffer.from('short string'),
        Buffer.from('A'.repeat(1000)),
        Buffer.alloc(100, 0),
        Buffer.alloc(100, 0xff),
        crypto.randomBytes(500),
        Buffer.from('\u0000\u0001\u0002\u0003'),
      ];

      for (const originalData of testCases) {
        const compressed = await compressData(originalData);
        const decompressed = await decompressData(compressed.compressedData);

        expect(
          decompressed.equals(originalData),
          `Round-trip failed for data of length ${originalData.length}`
        ).toBe(true);
      }
    });
  });

  describe('Error Handling', () => {
    it('should throw descriptive error for non-gzip data', async () => {
      const invalidData = Buffer.from('this is not gzip compressed data');

      await expect(decompressData(invalidData)).rejects.toThrow('Failed to decompress data:');
    });

    it('should throw descriptive error for truncated gzip data', async () => {
      const originalData = Buffer.from('test data');
      const compressed = await gzipAsync(originalData);
      // Truncate the compressed data
      const truncated = compressed.subarray(0, Math.floor(compressed.length / 2));

      await expect(decompressData(truncated)).rejects.toThrow('Failed to decompress data:');
    });

    it('should throw descriptive error for corrupted gzip data', async () => {
      const originalData = Buffer.from('test data');
      const compressed = await gzipAsync(originalData);
      // Corrupt the middle of the compressed data
      const corrupted = Buffer.from(compressed);
      const midpoint = Math.floor(corrupted.length / 2);
      corrupted[midpoint] = (corrupted[midpoint]! + 1) % 256;

      await expect(decompressData(corrupted)).rejects.toThrow('Failed to decompress data:');
    });

    it('should throw descriptive error for empty buffer', async () => {
      const emptyBuffer = Buffer.from('');

      await expect(decompressData(emptyBuffer)).rejects.toThrow('Failed to decompress data:');
    });

    it('should throw descriptive error for gzip magic bytes only', async () => {
      // Just the gzip magic number without valid content
      const magicOnly = Buffer.from([0x1f, 0x8b]);

      await expect(decompressData(magicOnly)).rejects.toThrow('Failed to decompress data:');
    });

    it('should throw descriptive error for partial gzip header', async () => {
      // Partial gzip header (magic + compression method but incomplete)
      const partialHeader = Buffer.from([0x1f, 0x8b, 0x08, 0x00]);

      await expect(decompressData(partialHeader)).rejects.toThrow('Failed to decompress data:');
    });

    it('should include original error message in thrown error for Error instances', async () => {
      const invalidData = Buffer.from('not gzip');

      try {
        await decompressData(invalidData);
        // Should not reach here
        expect.fail('Expected decompressData to throw');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const errorMessage = (error as Error).message;
        expect(errorMessage).toContain('Failed to decompress data:');
        // Should contain some information about why it failed
        expect(errorMessage.length).toBeGreaterThan('Failed to decompress data:'.length);
      }
    });

    it('should handle non-Error exceptions gracefully', async () => {
      // This tests the branch: error instanceof Error ? error.message : 'Unknown error'
      // We can't easily force a non-Error exception from gunzip, but we verify
      // the error handling format is consistent
      const invalidData = Buffer.from([0x00, 0x01, 0x02]);

      await expect(decompressData(invalidData)).rejects.toThrow('Failed to decompress data:');
    });

    it('should throw for random bytes that happen to start with gzip magic', async () => {
      // Random data that starts with gzip magic bytes but isn't valid
      const fakeGzip = Buffer.concat([Buffer.from([0x1f, 0x8b]), crypto.randomBytes(100)]);

      await expect(decompressData(fakeGzip)).rejects.toThrow('Failed to decompress data:');
    });
  });
});

describe('shouldCompress', () => {
  describe('Threshold Behavior', () => {
    it('should return false for size 0', () => {
      expect(shouldCompress(0)).toBe(false);
    });

    it('should return false for size 1', () => {
      expect(shouldCompress(1)).toBe(false);
    });

    it('should return false for size 149 (one below threshold)', () => {
      expect(shouldCompress(149)).toBe(false);
    });

    it('should return true for size 150 (exactly at threshold)', () => {
      expect(shouldCompress(150)).toBe(true);
    });

    it('should return true for size 151 (one above threshold)', () => {
      expect(shouldCompress(151)).toBe(true);
    });

    it('should return true for large sizes', () => {
      expect(shouldCompress(1000)).toBe(true);
      expect(shouldCompress(10000)).toBe(true);
      expect(shouldCompress(1000000)).toBe(true);
    });
  });

  describe('Boundary Values', () => {
    it('should return false for sizes 0 through 149', () => {
      for (let size = 0; size < 150; size++) {
        expect(shouldCompress(size), `size ${size} should return false`).toBe(false);
      }
    });

    it('should return true for sizes 150 through 300', () => {
      for (let size = 150; size <= 300; size++) {
        expect(shouldCompress(size), `size ${size} should return true`).toBe(true);
      }
    });
  });

  describe('Special Values', () => {
    it('should handle very large numbers', () => {
      expect(shouldCompress(Number.MAX_SAFE_INTEGER)).toBe(true);
    });

    it('should handle negative numbers (returns false as they are less than 150)', () => {
      // Negative sizes don't make sense but the function should handle them
      expect(shouldCompress(-1)).toBe(false);
      expect(shouldCompress(-100)).toBe(false);
      expect(shouldCompress(-150)).toBe(false);
    });

    it('should handle floating point numbers (implicit truncation behavior)', () => {
      // JavaScript comparison works with floats
      expect(shouldCompress(149.9)).toBe(false);
      expect(shouldCompress(150.0)).toBe(true);
      expect(shouldCompress(150.1)).toBe(true);
    });
  });

  describe('Return Type', () => {
    it('should return a boolean value', () => {
      expect(typeof shouldCompress(100)).toBe('boolean');
      expect(typeof shouldCompress(200)).toBe('boolean');
    });

    it('should return exactly false for values below threshold', () => {
      expect(shouldCompress(100)).toBe(false);
      expect(shouldCompress(100)).not.toBe(0);
      expect(shouldCompress(100)).not.toBe('');
      expect(shouldCompress(100)).not.toBe(null);
    });

    it('should return exactly true for values at or above threshold', () => {
      expect(shouldCompress(200)).toBe(true);
      expect(shouldCompress(200)).not.toBe(1);
      expect(shouldCompress(200)).not.toBe('true');
    });
  });
});

describe('Integration Tests', () => {
  describe('Compression Decision and Execution', () => {
    it('should not compress when shouldCompress returns false', async () => {
      const smallData = Buffer.from('tiny'); // 4 bytes, below threshold

      expect(shouldCompress(smallData.length)).toBe(false);

      // We can still compress it, but we would choose not to based on shouldCompress
      const result = await compressData(smallData);
      // For very small data, compressed size > original due to gzip overhead
      expect(result.compressedSize).toBeGreaterThanOrEqual(result.originalSize);
    });

    it('should compress when shouldCompress returns true', async () => {
      const largeCompressibleData = Buffer.from('A'.repeat(500)); // 500 bytes, above threshold

      expect(shouldCompress(largeCompressibleData.length)).toBe(true);

      const result = await compressData(largeCompressibleData);
      // For repetitive data above threshold, compression is effective
      expect(result.compressedSize).toBeLessThan(result.originalSize);
    });

    it('should demonstrate compression overhead for small files', async () => {
      // This shows why the 150-byte threshold exists
      const testSizes = [10, 50, 100, 149, 150, 200, 500];
      const results: Array<{
        size: number;
        compressed: number;
        ratio: number;
        shouldCompress: boolean;
      }> = [];

      for (const size of testSizes) {
        const data = Buffer.from('A'.repeat(size));
        const result = await compressData(data);
        results.push({
          size,
          compressed: result.compressedSize,
          ratio: result.compressedSize / result.originalSize,
          shouldCompress: shouldCompress(size),
        });
      }

      // Very small files have ratio > 1 (expansion due to gzip header)
      const verySmall = results.find((r) => r.size === 10);
      expect(verySmall?.ratio).toBeGreaterThan(1);

      // Larger files have ratio < 1 (actual compression)
      const larger = results.find((r) => r.size === 500);
      expect(larger?.ratio).toBeLessThan(1);
    });
  });

  describe('Complete Workflow', () => {
    it('should support full compression workflow: check -> compress -> decompress', async () => {
      const originalData = Buffer.from(
        'This is a document with enough content to be worth compressing. ' +
          'It contains repeated phrases and common English words that compress well. ' +
          'Adding more text to ensure we exceed the 150-byte compression threshold.'
      );

      // Step 1: Check if compression is worthwhile
      const worthCompressing = shouldCompress(originalData.length);
      expect(worthCompressing).toBe(true);

      // Step 2: Compress the data
      const compressionResult = await compressData(originalData);

      // Verify metadata
      expect(compressionResult.originalSize).toBe(originalData.length);
      expect(compressionResult.compressedSize).toBe(compressionResult.compressedData.length);
      expect(compressionResult.compressedSize).toBeLessThan(compressionResult.originalSize);

      // Step 3: Decompress and verify
      const decompressedData = await decompressData(compressionResult.compressedData);
      expect(decompressedData.equals(originalData)).toBe(true);
    });

    it('should handle workflow with data just at compression threshold', async () => {
      // Create data exactly at 150 bytes
      const data = Buffer.alloc(150, 'X');

      expect(shouldCompress(data.length)).toBe(true);
      expect(data.length).toBe(150);

      const compressed = await compressData(data);
      expect(compressed.originalSize).toBe(150);

      const decompressed = await decompressData(compressed.compressedData);
      expect(decompressed.equals(data)).toBe(true);
    });
  });
});
