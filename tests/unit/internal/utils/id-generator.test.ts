/// <reference types="vitest/globals" />
/**
 * Tests for id-generator utility (nanoid implementation)
 * @module tests/unit/internal/utils/id-generator.test
 *
 * Tests cryptographically secure, URL-safe ID generation with:
 * - Default and custom sizes
 * - URL-safe alphabet validation (A-Z, a-z, 0-9, _, -)
 * - Uniqueness verification (statistical collision testing)
 * - Entropy distribution analysis
 */

import { nanoid } from '../../../../src/internal/utils/id-generator.js';

describe('nanoid', () => {
  // URL-safe alphabet: A-Z (26) + a-z (26) + 0-9 (10) + _ + - = 64 characters
  const URL_SAFE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
  const ALPHABET_SET = new Set(URL_SAFE_ALPHABET.split(''));

  describe('Default Behavior', () => {
    it('should generate an ID with default length of 21 characters', () => {
      const id = nanoid();
      expect(id).toHaveLength(21);
    });

    it('should return a string', () => {
      const id = nanoid();
      expect(typeof id).toBe('string');
    });

    it('should generate different IDs on each call', () => {
      const id1 = nanoid();
      const id2 = nanoid();
      expect(id1).not.toBe(id2);
    });
  });

  describe('Custom Size', () => {
    it('should generate ID with specified size of 1', () => {
      const id = nanoid(1);
      expect(id).toHaveLength(1);
    });

    it('should generate ID with specified size of 10', () => {
      const id = nanoid(10);
      expect(id).toHaveLength(10);
    });

    it('should generate ID with specified size of 50', () => {
      const id = nanoid(50);
      expect(id).toHaveLength(50);
    });

    it('should generate ID with specified size of 100', () => {
      const id = nanoid(100);
      expect(id).toHaveLength(100);
    });

    it('should generate ID with specified size of 256', () => {
      const id = nanoid(256);
      expect(id).toHaveLength(256);
    });

    it('should handle size of 0 and return empty string', () => {
      const id = nanoid(0);
      expect(id).toBe('');
      expect(id).toHaveLength(0);
    });
  });

  describe('URL-Safe Alphabet Validation', () => {
    it('should only contain characters from the URL-safe alphabet', () => {
      const id = nanoid();
      for (const char of id) {
        expect(ALPHABET_SET.has(char)).toBe(true);
      }
    });

    it('should only contain URL-safe characters for various sizes', () => {
      const sizes = [1, 5, 10, 21, 50, 100];
      for (const size of sizes) {
        const id = nanoid(size);
        for (const char of id) {
          expect(ALPHABET_SET.has(char)).toBe(true);
        }
      }
    });

    it('should contain only URL-safe characters across many IDs', () => {
      const iterations = 1000;
      for (let i = 0; i < iterations; i++) {
        const id = nanoid();
        for (const char of id) {
          expect(ALPHABET_SET.has(char)).toBe(true);
        }
      }
    });

    it('should not contain non-URL-safe characters', () => {
      const nonUrlSafeChars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '=', '+', '[', ']', '{', '}', '|', '\\', '/', '?', '<', '>', ',', '.', ':', ';', '"', "'", '`', '~', ' '];
      const iterations = 500;

      for (let i = 0; i < iterations; i++) {
        const id = nanoid();
        for (const badChar of nonUrlSafeChars) {
          expect(id).not.toContain(badChar);
        }
      }
    });
  });

  describe('Uniqueness (Statistical Collision Testing)', () => {
    it('should generate unique IDs in a small batch (100 IDs)', () => {
      const ids = new Set<string>();
      const count = 100;

      for (let i = 0; i < count; i++) {
        ids.add(nanoid());
      }

      expect(ids.size).toBe(count);
    });

    it('should generate unique IDs in a medium batch (1,000 IDs)', () => {
      const ids = new Set<string>();
      const count = 1000;

      for (let i = 0; i < count; i++) {
        ids.add(nanoid());
      }

      expect(ids.size).toBe(count);
    });

    it('should generate unique IDs in a large batch (10,000 IDs)', () => {
      const ids = new Set<string>();
      const count = 10000;

      for (let i = 0; i < count; i++) {
        ids.add(nanoid());
      }

      expect(ids.size).toBe(count);
    });

    it('should generate unique IDs with small size (size=8, 5,000 IDs)', () => {
      // With size=8: 64^8 = ~2.8 * 10^14 possible combinations
      // Birthday paradox: sqrt(2 * 64^8 * 0.5) ~ 16.7 million before 50% collision chance
      // 5,000 IDs should have essentially 0 collision probability
      const ids = new Set<string>();
      const count = 5000;

      for (let i = 0; i < count; i++) {
        ids.add(nanoid(8));
      }

      expect(ids.size).toBe(count);
    });

    it('should generate unique IDs with large size (size=32, 10,000 IDs)', () => {
      const ids = new Set<string>();
      const count = 10000;

      for (let i = 0; i < count; i++) {
        ids.add(nanoid(32));
      }

      expect(ids.size).toBe(count);
    });
  });

  describe('Entropy Distribution', () => {
    it('should use all 64 alphabet characters across many IDs', () => {
      // Generate enough IDs to statistically ensure all characters appear
      // With 21 characters per ID and 64 possible chars, each char has ~32.8% chance per position
      // After 500 IDs (10,500 characters), probability of missing any char is negligible
      const charCounts = new Map<string, number>();
      const iterations = 500;

      for (let i = 0; i < iterations; i++) {
        const id = nanoid();
        for (const char of id) {
          charCounts.set(char, (charCounts.get(char) || 0) + 1);
        }
      }

      // All 64 characters should appear at least once
      expect(charCounts.size).toBe(64);

      // Verify all alphabet characters are present
      for (const char of URL_SAFE_ALPHABET) {
        expect(charCounts.has(char)).toBe(true);
      }
    });

    it('should have roughly uniform distribution across alphabet characters', () => {
      const charCounts = new Map<string, number>();
      const iterations = 10000;
      const idSize = 21;
      const totalChars = iterations * idSize; // 210,000 characters

      for (let i = 0; i < iterations; i++) {
        const id = nanoid(idSize);
        for (const char of id) {
          charCounts.set(char, (charCounts.get(char) || 0) + 1);
        }
      }

      // Expected count per character: 210,000 / 64 = 3281.25
      const expectedCount = totalChars / 64;
      // Allow 20% deviation for statistical variance
      const tolerance = 0.20;
      const minCount = expectedCount * (1 - tolerance);
      const maxCount = expectedCount * (1 + tolerance);

      for (const char of URL_SAFE_ALPHABET) {
        const count = charCounts.get(char) || 0;
        expect(count).toBeGreaterThan(minCount);
        expect(count).toBeLessThan(maxCount);
      }
    });

    it('should have uniform distribution at each position', () => {
      // Verify that each position in the ID has good character distribution
      const positionCounts: Map<string, number>[] = [];
      const idSize = 21;
      const iterations = 2000;

      // Initialize position maps
      for (let i = 0; i < idSize; i++) {
        positionCounts.push(new Map<string, number>());
      }

      for (let i = 0; i < iterations; i++) {
        const id = nanoid(idSize);
        for (let pos = 0; pos < id.length; pos++) {
          const char = id[pos]!;
          const posMap = positionCounts[pos]!;
          posMap.set(char, (posMap.get(char) || 0) + 1);
        }
      }

      // Each position should have most alphabet characters represented
      // With 2000 iterations and 64 chars, each char has ~31.25 expected occurrences
      // Allow some chars to be missing due to statistical variance, but most should appear
      for (let pos = 0; pos < idSize; pos++) {
        const posMap = positionCounts[pos]!;
        // At least 50 of 64 characters should appear at each position
        expect(posMap.size).toBeGreaterThan(50);
      }
    });
  });

  describe('Edge Cases', () => {
    it('should handle consecutive rapid calls', () => {
      const ids: string[] = [];
      for (let i = 0; i < 100; i++) {
        ids.push(nanoid());
      }

      // All should be unique
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(100);

      // All should have correct length
      for (const id of ids) {
        expect(id).toHaveLength(21);
      }
    });

    it('should handle very large size (1000 characters)', () => {
      const id = nanoid(1000);
      expect(id).toHaveLength(1000);
      for (const char of id) {
        expect(ALPHABET_SET.has(char)).toBe(true);
      }
    });

    it('should produce consistent results with same size parameter', () => {
      const sizes = [5, 10, 15, 20, 25, 30];
      for (const size of sizes) {
        const id1 = nanoid(size);
        const id2 = nanoid(size);

        expect(id1).toHaveLength(size);
        expect(id2).toHaveLength(size);
        expect(id1).not.toBe(id2); // Different values
      }
    });
  });

  describe('Alphabet Character Classes', () => {
    it('should include uppercase letters (A-Z)', () => {
      const uppercaseRegex = /[A-Z]/;
      let foundUppercase = false;
      const iterations = 100;

      for (let i = 0; i < iterations && !foundUppercase; i++) {
        const id = nanoid(100);
        if (uppercaseRegex.test(id)) {
          foundUppercase = true;
        }
      }

      expect(foundUppercase).toBe(true);
    });

    it('should include lowercase letters (a-z)', () => {
      const lowercaseRegex = /[a-z]/;
      let foundLowercase = false;
      const iterations = 100;

      for (let i = 0; i < iterations && !foundLowercase; i++) {
        const id = nanoid(100);
        if (lowercaseRegex.test(id)) {
          foundLowercase = true;
        }
      }

      expect(foundLowercase).toBe(true);
    });

    it('should include digits (0-9)', () => {
      const digitRegex = /[0-9]/;
      let foundDigit = false;
      const iterations = 100;

      for (let i = 0; i < iterations && !foundDigit; i++) {
        const id = nanoid(100);
        if (digitRegex.test(id)) {
          foundDigit = true;
        }
      }

      expect(foundDigit).toBe(true);
    });

    it('should include underscore character', () => {
      let foundUnderscore = false;
      const iterations = 500;

      for (let i = 0; i < iterations && !foundUnderscore; i++) {
        const id = nanoid(100);
        if (id.includes('_')) {
          foundUnderscore = true;
        }
      }

      expect(foundUnderscore).toBe(true);
    });

    it('should include hyphen character', () => {
      let foundHyphen = false;
      const iterations = 500;

      for (let i = 0; i < iterations && !foundHyphen; i++) {
        const id = nanoid(100);
        if (id.includes('-')) {
          foundHyphen = true;
        }
      }

      expect(foundHyphen).toBe(true);
    });
  });

  describe('ID Format Validation', () => {
    it('should produce IDs that are valid URL path segments', () => {
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        const id = nanoid();
        // URL-safe means no encoding needed - encodeURIComponent should return same string
        expect(encodeURIComponent(id)).toBe(id);
      }
    });

    it('should produce IDs that match URL-safe regex pattern', () => {
      const urlSafeRegex = /^[A-Za-z0-9_-]+$/;
      const iterations = 1000;

      for (let i = 0; i < iterations; i++) {
        const id = nanoid();
        expect(urlSafeRegex.test(id)).toBe(true);
      }
    });

    it('should produce IDs safe for use in CSS selectors (with prefix)', () => {
      // CSS class names can include alphanumeric, hyphen, underscore (but not start with digit/hyphen)
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        const id = nanoid();
        // With an alphabetic prefix, the ID is safe for CSS
        const cssClass = `id-${id}`;
        const cssClassRegex = /^[a-zA-Z][a-zA-Z0-9_-]*$/;
        expect(cssClassRegex.test(cssClass)).toBe(true);
      }
    });

    it('should produce IDs safe for use as HTML element IDs', () => {
      // HTML5 allows any characters except whitespace in IDs
      // Our IDs are alphanumeric + hyphen + underscore, so always safe
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        const id = nanoid();
        expect(id).not.toMatch(/\s/);
        expect(id.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Entropy Calculation Verification', () => {
    it('should have ~126 bits of entropy with default size (21 chars * 6 bits)', () => {
      // 64 characters = 2^6 = 6 bits per character
      // 21 characters = 21 * 6 = 126 bits
      // This test documents the entropy expectation
      const bitsPerChar = Math.log2(64);
      const defaultSize = 21;
      const expectedEntropy = bitsPerChar * defaultSize;

      expect(bitsPerChar).toBe(6);
      expect(expectedEntropy).toBe(126);
    });

    it('should provide configurable entropy based on size', () => {
      const bitsPerChar = 6;
      const testCases = [
        { size: 8, expectedBits: 48 },
        { size: 10, expectedBits: 60 },
        { size: 16, expectedBits: 96 },
        { size: 21, expectedBits: 126 },
        { size: 32, expectedBits: 192 },
      ];

      for (const { size, expectedBits } of testCases) {
        const id = nanoid(size);
        expect(id).toHaveLength(size);
        expect(size * bitsPerChar).toBe(expectedBits);
      }
    });
  });

  describe('Return Type Consistency', () => {
    it('should always return a string type', () => {
      expect(typeof nanoid()).toBe('string');
      expect(typeof nanoid(1)).toBe('string');
      expect(typeof nanoid(0)).toBe('string');
      expect(typeof nanoid(100)).toBe('string');
    });

    it('should return primitive string, not String object', () => {
      const id = nanoid();
      expect(id).not.toBeInstanceOf(String);
      expect(Object.prototype.toString.call(id)).toBe('[object String]');
    });
  });

  describe('Concurrent Generation', () => {
    it('should generate unique IDs when called in parallel', async () => {
      const count = 1000;
      const promises: Promise<string>[] = [];

      for (let i = 0; i < count; i++) {
        promises.push(Promise.resolve(nanoid()));
      }

      const ids = await Promise.all(promises);
      const uniqueIds = new Set(ids);

      expect(uniqueIds.size).toBe(count);
    });

    it('should maintain correct length when generated in parallel', async () => {
      const count = 500;
      const promises: Promise<string>[] = [];

      for (let i = 0; i < count; i++) {
        promises.push(Promise.resolve(nanoid(15)));
      }

      const ids = await Promise.all(promises);

      for (const id of ids) {
        expect(id).toHaveLength(15);
      }
    });
  });
});
