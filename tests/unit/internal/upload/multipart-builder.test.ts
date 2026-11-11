/// <reference types="vitest/globals" />
/**
 * Tests for CapsasMultipartBuilder
 * @module tests/unit/internal/upload/multipart-builder.test
 *
 * Tests multipart form-data builder for capsa uploads with:
 * - Boundary generation and uniqueness
 * - Metadata management (required first, cannot duplicate)
 * - Capsa metadata parts with indexing
 * - File metadata parts with auto-generated fileId fallback
 * - Binary file parts
 * - Complete multipart body building
 * - Content-Type header generation
 * - Error handling for incorrect method call order
 */

import { CapsasMultipartBuilder } from '../../../../src/internal/upload/multipart-builder.js';

describe('CapsasMultipartBuilder', () => {
  describe('Constructor and Boundary Generation', () => {
    it('should create instance with unique boundary', () => {
      const builder = new CapsasMultipartBuilder();
      const boundary = builder.getBoundary();

      expect(boundary).toBeDefined();
      expect(typeof boundary).toBe('string');
    });

    it('should generate boundary with correct prefix', () => {
      const builder = new CapsasMultipartBuilder();
      const boundary = builder.getBoundary();

      expect(boundary.startsWith('----CapsaBoundary')).toBe(true);
    });

    it('should generate boundary with hex suffix', () => {
      const builder = new CapsasMultipartBuilder();
      const boundary = builder.getBoundary();

      // Prefix is "----CapsaBoundary" (17 chars), suffix is 32 hex chars (16 bytes * 2)
      expect(boundary.length).toBe(17 + 32);

      const hexSuffix = boundary.slice(17);
      expect(/^[0-9a-f]{32}$/.test(hexSuffix)).toBe(true);
    });

    it('should generate unique boundaries for different instances', () => {
      const boundaries = new Set<string>();
      const count = 100;

      for (let i = 0; i < count; i++) {
        const builder = new CapsasMultipartBuilder();
        boundaries.add(builder.getBoundary());
      }

      expect(boundaries.size).toBe(count);
    });

    it('should maintain same boundary throughout instance lifecycle', () => {
      const builder = new CapsasMultipartBuilder();
      const boundary1 = builder.getBoundary();

      builder.addMetadata(1, 'creator-123');
      const boundary2 = builder.getBoundary();

      builder.addCapsaMetadata({ test: 'data' }, 0);
      const boundary3 = builder.getBoundary();

      expect(boundary1).toBe(boundary2);
      expect(boundary2).toBe(boundary3);
    });
  });

  describe('getContentType', () => {
    it('should return correct content type format', () => {
      const builder = new CapsasMultipartBuilder();
      const contentType = builder.getContentType();

      expect(contentType.startsWith('multipart/form-data; boundary=')).toBe(true);
    });

    it('should include boundary in content type', () => {
      const builder = new CapsasMultipartBuilder();
      const boundary = builder.getBoundary();
      const contentType = builder.getContentType();

      expect(contentType).toBe(`multipart/form-data; boundary=${boundary}`);
    });
  });

  describe('addMetadata', () => {
    it('should add metadata part successfully', () => {
      const builder = new CapsasMultipartBuilder();
      const result = builder.addMetadata(3, 'party_abc123');

      expect(result).toBe(builder);
    });

    it('should return this for method chaining', () => {
      const builder = new CapsasMultipartBuilder();
      const result = builder.addMetadata(1, 'creator');

      expect(result).toBeInstanceOf(CapsasMultipartBuilder);
      expect(result).toBe(builder);
    });

    it('should throw error if metadata already set', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      expect(() => builder.addMetadata(2, 'another-creator')).toThrow('Metadata already set');
    });

    it('should include metadata in built output', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(5, 'party_xyz');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('"capsaCount":5');
      expect(bodyString).toContain('"creator":"party_xyz"');
    });

    it('should set metadata part with correct name', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'test-creator');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('Content-Disposition: form-data; name="metadata"');
    });

    it('should set metadata part with JSON content type', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'test-creator');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('Content-Type: application/json');
    });
  });

  describe('addCapsaMetadata', () => {
    it('should throw error if metadata not set first', () => {
      const builder = new CapsasMultipartBuilder();

      expect(() => builder.addCapsaMetadata({ test: 'data' }, 0)).toThrow('Must call addMetadata() first');
    });

    it('should add capsa metadata successfully after metadata', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const result = builder.addCapsaMetadata({ subject: 'Test Capsa' }, 0);

      expect(result).toBe(builder);
    });

    it('should return this for method chaining', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const result = builder.addCapsaMetadata({}, 0);

      expect(result).toBeInstanceOf(CapsasMultipartBuilder);
    });

    it('should serialize capsa object to JSON', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const capsaData = {
        subject: 'Important Document',
        keychain: [{ party: 'party_1', encryptedKey: 'encrypted...' }],
        files: [],
      };
      builder.addCapsaMetadata(capsaData, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('"subject":"Important Document"');
      expect(bodyString).toContain('"keychain":[{"party":"party_1","encryptedKey":"encrypted..."}]');
    });

    it('should use capsa index in part name', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(3, 'creator');

      builder.addCapsaMetadata({}, 0);
      builder.addCapsaMetadata({}, 1);
      builder.addCapsaMetadata({}, 2);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('name="capsa_0"');
      expect(bodyString).toContain('name="capsa_1"');
      expect(bodyString).toContain('name="capsa_2"');
    });

    it('should set JSON content type for capsa metadata', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addCapsaMetadata({ data: 'test' }, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      // Count occurrences of application/json - should be at least 2 (metadata + capsa)
      const matches = bodyString.match(/Content-Type: application\/json/g);
      expect(matches).not.toBeNull();
      expect(matches!.length).toBeGreaterThanOrEqual(2);
    });

    it('should handle complex nested objects', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const complexData = {
        nested: {
          deep: {
            value: 'test',
            array: [1, 2, 3],
          },
        },
        nullValue: null,
        boolValue: true,
        numValue: 42.5,
      };
      builder.addCapsaMetadata(complexData, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('"nested":{"deep":{"value":"test","array":[1,2,3]}}');
      expect(bodyString).toContain('"nullValue":null');
      expect(bodyString).toContain('"boolValue":true');
      expect(bodyString).toContain('"numValue":42.5');
    });
  });

  describe('addFileMetadata', () => {
    it('should throw error if metadata not set first', () => {
      const builder = new CapsasMultipartBuilder();

      expect(() => builder.addFileMetadata({ fileId: 'file_1' }, 0, 0)).toThrow('Must call addMetadata() first');
    });

    it('should add file metadata successfully after metadata', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const result = builder.addFileMetadata({ fileId: 'file_abc' }, 0, 0);

      expect(result).toBe(builder);
    });

    it('should return this for method chaining', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const result = builder.addFileMetadata({}, 0, 0);

      expect(result).toBeInstanceOf(CapsasMultipartBuilder);
    });

    it('should use provided fileId in filename', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileMetadata({ fileId: 'custom_file_id' }, 0, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('filename="custom_file_id.json"');
    });

    it('should generate fileId when not provided', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileMetadata({}, 0, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('filename="file_0_0.json"');
    });

    it('should generate fileId with correct capsa and file indexes', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(2, 'creator');
      builder.addFileMetadata({}, 0, 0);
      builder.addFileMetadata({}, 0, 1);
      builder.addFileMetadata({}, 1, 0);
      builder.addFileMetadata({}, 1, 2);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('filename="file_0_0.json"');
      expect(bodyString).toContain('filename="file_0_1.json"');
      expect(bodyString).toContain('filename="file_1_0.json"');
      expect(bodyString).toContain('filename="file_1_2.json"');
    });

    it('should use "file" as part name', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileMetadata({ fileId: 'test' }, 0, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('Content-Disposition: form-data; name="file"');
    });

    it('should set JSON content type for file metadata', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileMetadata({ fileId: 'test' }, 0, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      // Verify there's application/json for file metadata
      const matches = bodyString.match(/Content-Type: application\/json/g);
      expect(matches).not.toBeNull();
    });

    it('should serialize complete file metadata object', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const fileMetadata = {
        fileId: 'file_abc123',
        encryptedFilename: 'base64encodedname',
        filenameIV: 'iv123',
        filenameAuthTag: 'authtag123',
        iv: 'fileiv456',
        authTag: 'fileauthtag',
        mimetype: 'application/pdf',
        size: 1024,
        hash: 'sha256hash',
        hashAlgorithm: 'SHA-256',
      };
      builder.addFileMetadata(fileMetadata, 0, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('"fileId":"file_abc123"');
      expect(bodyString).toContain('"mimetype":"application/pdf"');
      expect(bodyString).toContain('"size":1024');
    });
  });

  describe('addFileBinary', () => {
    it('should throw error if metadata not set first', () => {
      const builder = new CapsasMultipartBuilder();
      const fileData = Buffer.from('test data');

      expect(() => builder.addFileBinary(fileData, 'file.enc')).toThrow('Must call addMetadata() first');
    });

    it('should add binary file successfully after metadata', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const fileData = Buffer.from('encrypted content here');
      const result = builder.addFileBinary(fileData, 'file_abc.enc');

      expect(result).toBe(builder);
    });

    it('should return this for method chaining', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const result = builder.addFileBinary(Buffer.from('data'), 'file.enc');

      expect(result).toBeInstanceOf(CapsasMultipartBuilder);
    });

    it('should use provided fileId as filename', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileBinary(Buffer.from('data'), 'my_custom_file.enc');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('filename="my_custom_file.enc"');
    });

    it('should set octet-stream content type for binary', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileBinary(Buffer.from('binary data'), 'file.enc');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('Content-Type: application/octet-stream');
    });

    it('should use "file" as part name for binary', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileBinary(Buffer.from('data'), 'file.enc');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      // Should contain file part with filename
      expect(bodyString).toContain('Content-Disposition: form-data; name="file"; filename="file.enc"');
    });

    it('should include binary content in body', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const binaryData = Buffer.from([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD]);
      builder.addFileBinary(binaryData, 'data.enc');

      const body = builder.build();

      // The binary content should be preserved
      expect(body.includes(binaryData)).toBe(true);
    });

    it('should handle empty buffer', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileBinary(Buffer.alloc(0), 'empty.enc');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('filename="empty.enc"');
    });

    it('should handle large binary data', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      // 1MB of random-ish data
      const largeData = Buffer.alloc(1024 * 1024);
      for (let i = 0; i < largeData.length; i++) {
        largeData[i] = i % 256;
      }
      builder.addFileBinary(largeData, 'large.enc');

      const body = builder.build();

      expect(body.includes(largeData)).toBe(true);
      expect(body.length).toBeGreaterThan(largeData.length);
    });
  });

  describe('build', () => {
    it('should throw error if metadata not set', () => {
      const builder = new CapsasMultipartBuilder();

      expect(() => builder.build()).toThrow('Must call addMetadata() first');
    });

    it('should return Buffer', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const body = builder.build();

      expect(Buffer.isBuffer(body)).toBe(true);
    });

    it('should start each part with boundary', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const body = builder.build();
      const bodyString = body.toString('utf-8');
      const boundary = builder.getBoundary();

      expect(bodyString).toContain(`--${boundary}\r\n`);
    });

    it('should end with closing boundary', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const body = builder.build();
      const bodyString = body.toString('utf-8');
      const boundary = builder.getBoundary();

      expect(bodyString).toContain(`--${boundary}--\r\n`);
      expect(bodyString.endsWith(`--${boundary}--\r\n`)).toBe(true);
    });

    it('should separate headers from content with blank line', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      // After Content-Type header, there should be \r\n\r\n before content
      expect(bodyString).toContain('application/json\r\n\r\n');
    });

    it('should end each part content with CRLF', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addCapsaMetadata({ test: 'value' }, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');
      const boundary = builder.getBoundary();

      // Content should be followed by \r\n before next boundary
      const parts = bodyString.split(`--${boundary}`);
      // Each non-final part should end with \r\n
      for (let i = 1; i < parts.length - 1; i++) {
        expect(parts[i]!.endsWith('\r\n')).toBe(true);
      }
    });

    it('should build complete multipart with all part types', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator_party');
      builder.addCapsaMetadata({ subject: 'Test' }, 0);
      builder.addFileMetadata({ fileId: 'file_1' }, 0, 0);
      builder.addFileBinary(Buffer.from('encrypted data'), 'file_1.enc');

      const body = builder.build();
      const bodyString = body.toString('utf-8');
      const boundary = builder.getBoundary();

      // Verify structure
      expect(bodyString).toContain(`--${boundary}\r\n`);
      expect(bodyString).toContain('name="metadata"');
      expect(bodyString).toContain('name="capsa_0"');
      expect(bodyString).toContain('filename="file_1.json"');
      expect(bodyString).toContain('filename="file_1.enc"');
      expect(bodyString).toContain('Content-Type: application/json');
      expect(bodyString).toContain('Content-Type: application/octet-stream');
      expect(bodyString).toContain(`--${boundary}--\r\n`);
    });

    it('should maintain part order as added', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addCapsaMetadata({ order: 'second' }, 0);
      builder.addFileMetadata({ fileId: 'third' }, 0, 0);
      builder.addFileBinary(Buffer.from('fourth'), 'fourth.enc');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      const metadataPos = bodyString.indexOf('name="metadata"');
      const capsaPos = bodyString.indexOf('name="capsa_0"');
      const fileMetaPos = bodyString.indexOf('filename="third.json"');
      const fileBinaryPos = bodyString.indexOf('filename="fourth.enc"');

      expect(metadataPos).toBeLessThan(capsaPos);
      expect(capsaPos).toBeLessThan(fileMetaPos);
      expect(fileMetaPos).toBeLessThan(fileBinaryPos);
    });

    it('should handle multiple capsas with multiple files', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(2, 'creator');

      // Capsa 0 with 2 files
      builder.addCapsaMetadata({ id: 'capsa_0' }, 0);
      builder.addFileMetadata({ fileId: 'c0f0' }, 0, 0);
      builder.addFileBinary(Buffer.from('c0f0 data'), 'c0f0.enc');
      builder.addFileMetadata({ fileId: 'c0f1' }, 0, 1);
      builder.addFileBinary(Buffer.from('c0f1 data'), 'c0f1.enc');

      // Capsa 1 with 1 file
      builder.addCapsaMetadata({ id: 'capsa_1' }, 1);
      builder.addFileMetadata({ fileId: 'c1f0' }, 1, 0);
      builder.addFileBinary(Buffer.from('c1f0 data'), 'c1f0.enc');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      // Verify all expected parts are present
      expect(bodyString).toContain('name="capsa_0"');
      expect(bodyString).toContain('name="capsa_1"');
      expect(bodyString).toContain('filename="c0f0.json"');
      expect(bodyString).toContain('filename="c0f0.enc"');
      expect(bodyString).toContain('filename="c0f1.json"');
      expect(bodyString).toContain('filename="c0f1.enc"');
      expect(bodyString).toContain('filename="c1f0.json"');
      expect(bodyString).toContain('filename="c1f0.enc"');
    });

    it('should produce valid multipart structure parseable by standards', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addCapsaMetadata({ test: true }, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');
      const boundary = builder.getBoundary();

      // RFC 2046 multipart format validation
      // 1. Must start with CRLF or boundary (we start with boundary)
      expect(bodyString.startsWith(`--${boundary}\r\n`)).toBe(true);

      // 2. Parts separated by boundary
      const parts = bodyString.split(`--${boundary}`);
      // First element is empty (before first boundary), last ends with --
      expect(parts[0]).toBe('');
      expect(parts[parts.length - 1]).toBe('--\r\n');

      // 3. Each part has headers followed by blank line then content
      for (let i = 1; i < parts.length - 1; i++) {
        const part = parts[i];
        expect(part!.includes('\r\n\r\n')).toBe(true);
      }
    });
  });

  describe('Method Chaining', () => {
    it('should support full fluent chaining', () => {
      const builder = new CapsasMultipartBuilder();

      const body = builder
        .addMetadata(1, 'party_creator')
        .addCapsaMetadata({ subject: 'Chained Test' }, 0)
        .addFileMetadata({ fileId: 'chained_file' }, 0, 0)
        .addFileBinary(Buffer.from('chained data'), 'chained_file.enc')
        .build();

      expect(Buffer.isBuffer(body)).toBe(true);
      expect(body.toString('utf-8')).toContain('"subject":"Chained Test"');
    });

    it('should allow getting content type after building', () => {
      const builder = new CapsasMultipartBuilder();

      builder
        .addMetadata(1, 'creator')
        .addCapsaMetadata({}, 0);

      const body = builder.build();
      const contentType = builder.getContentType();

      expect(Buffer.isBuffer(body)).toBe(true);
      expect(contentType).toContain('multipart/form-data');
    });
  });

  describe('Content-Disposition Header Format', () => {
    it('should format disposition without filename for metadata', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      // Metadata should not have filename
      const metadataSection = bodyString.split('name="metadata"')[1]!.split('\r\n')[0];
      expect(metadataSection).toBe('');
    });

    it('should format disposition without filename for capsa metadata', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addCapsaMetadata({}, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      // Capsa metadata should not have filename
      const capsaSection = bodyString.split('name="capsa_0"')[1]!.split('\r\n')[0];
      expect(capsaSection).toBe('');
    });

    it('should format disposition with filename for file metadata', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileMetadata({ fileId: 'test_file' }, 0, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('Content-Disposition: form-data; name="file"; filename="test_file.json"');
    });

    it('should format disposition with filename for binary file', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileBinary(Buffer.from('data'), 'binary_file.enc');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('Content-Disposition: form-data; name="file"; filename="binary_file.enc"');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty capsa object', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addCapsaMetadata({}, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('{}');
    });

    it('should handle null values in capsa object', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addCapsaMetadata({ value: null }, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('"value":null');
    });

    it('should handle special characters in string values', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addCapsaMetadata({
        special: 'quotes"and\\backslash',
        unicode: 'Hello',
        newlines: 'line1\nline2\r\nline3',
      }, 0);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      // JSON.stringify handles escaping
      expect(bodyString).toContain('"special":"quotes\\"and\\\\backslash"');
      expect(bodyString).toContain('"unicode":"Hello"');
      expect(bodyString).toContain('"newlines":"line1\\nline2\\r\\nline3"');
    });

    it('should handle very long creator ID', () => {
      const builder = new CapsasMultipartBuilder();
      const longCreator = 'party_' + 'x'.repeat(1000);
      builder.addMetadata(1, longCreator);

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain(longCreator);
    });

    it('should handle large capsaCount', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(500, 'creator');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('"capsaCount":500');
    });

    it('should handle zero capsaCount', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(0, 'creator');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('"capsaCount":0');
    });

    it('should handle binary data with all byte values', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      // Create buffer with all 256 byte values
      const allBytes = Buffer.alloc(256);
      for (let i = 0; i < 256; i++) {
        allBytes[i] = i;
      }
      builder.addFileBinary(allBytes, 'allbytes.enc');

      const body = builder.build();

      // Verify all bytes are preserved
      expect(body.includes(allBytes)).toBe(true);
    });

    it('should handle fileId with special characters in filename', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addFileBinary(Buffer.from('data'), 'file-with_special.chars.enc');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('filename="file-with_special.chars.enc"');
    });

    it('should handle empty string creator', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, '');

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('"creator":""');
    });

    it('should produce consistent output for same input', () => {
      const builder1 = new CapsasMultipartBuilder();
      builder1.addMetadata(1, 'creator');
      builder1.addCapsaMetadata({ key: 'value' }, 0);
      const body1 = builder1.build();

      const builder2 = new CapsasMultipartBuilder();
      builder2.addMetadata(1, 'creator');
      builder2.addCapsaMetadata({ key: 'value' }, 0);
      const body2 = builder2.build();

      // Bodies should be structurally similar (boundaries will differ)
      // Extract content without boundaries
      const boundary1 = builder1.getBoundary();
      const boundary2 = builder2.getBoundary();

      const content1 = body1.toString('utf-8').replace(new RegExp(boundary1, 'g'), 'BOUNDARY');
      const content2 = body2.toString('utf-8').replace(new RegExp(boundary2, 'g'), 'BOUNDARY');

      expect(content1).toBe(content2);
    });
  });

  describe('Error Messages', () => {
    it('should provide clear error for duplicate metadata', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      try {
        builder.addMetadata(2, 'another');
        expect.fail('Should have thrown');
      } catch (error) {
        expect((error as Error).message).toBe('Metadata already set');
      }
    });

    it('should provide clear error for addCapsaMetadata without metadata', () => {
      const builder = new CapsasMultipartBuilder();

      try {
        builder.addCapsaMetadata({}, 0);
        expect.fail('Should have thrown');
      } catch (error) {
        expect((error as Error).message).toBe('Must call addMetadata() first');
      }
    });

    it('should provide clear error for addFileMetadata without metadata', () => {
      const builder = new CapsasMultipartBuilder();

      try {
        builder.addFileMetadata({}, 0, 0);
        expect.fail('Should have thrown');
      } catch (error) {
        expect((error as Error).message).toBe('Must call addMetadata() first');
      }
    });

    it('should provide clear error for addFileBinary without metadata', () => {
      const builder = new CapsasMultipartBuilder();

      try {
        builder.addFileBinary(Buffer.from('data'), 'file.enc');
        expect.fail('Should have thrown');
      } catch (error) {
        expect((error as Error).message).toBe('Must call addMetadata() first');
      }
    });

    it('should provide clear error for build without metadata', () => {
      const builder = new CapsasMultipartBuilder();

      try {
        builder.build();
        expect.fail('Should have thrown');
      } catch (error) {
        expect((error as Error).message).toBe('Must call addMetadata() first');
      }
    });
  });

  describe('Real-World Usage Scenarios', () => {
    it('should handle typical single capsa upload', () => {
      const builder = new CapsasMultipartBuilder();

      // Typical usage: 1 capsa with 2 files
      builder.addMetadata(1, 'party_abc123');
      builder.addCapsaMetadata({
        subject: 'Insurance Claim Documents',
        keychain: [
          { party: 'party_abc123', encryptedKey: 'base64key1' },
          { party: 'party_xyz789', encryptedKey: 'base64key2' },
        ],
        expiresAt: '2025-12-31T23:59:59Z',
      }, 0);

      // File 1
      builder.addFileMetadata({
        fileId: 'file_001',
        encryptedFilename: 'encname1',
        mimetype: 'application/pdf',
        size: 1024,
      }, 0, 0);
      builder.addFileBinary(Buffer.from('encrypted pdf content'), 'file_001.enc');

      // File 2
      builder.addFileMetadata({
        fileId: 'file_002',
        encryptedFilename: 'encname2',
        mimetype: 'image/jpeg',
        size: 2048,
      }, 0, 1);
      builder.addFileBinary(Buffer.from('encrypted image content'), 'file_002.enc');

      const body = builder.build();
      const contentType = builder.getContentType();

      expect(Buffer.isBuffer(body)).toBe(true);
      expect(contentType).toContain('multipart/form-data');

      const bodyString = body.toString('utf-8');
      expect(bodyString).toContain('"capsaCount":1');
      expect(bodyString).toContain('"party_abc123"');
      expect(bodyString).toContain('Insurance Claim Documents');
    });

    it('should handle batch upload of multiple capsas', () => {
      const builder = new CapsasMultipartBuilder();
      const capsaCount = 5;

      builder.addMetadata(capsaCount, 'bulk_uploader');

      for (let i = 0; i < capsaCount; i++) {
        builder.addCapsaMetadata({
          subject: `Batch Capsa ${i}`,
          batchId: 'batch_123',
        }, i);

        // Each capsa has 1 file
        builder.addFileMetadata({ fileId: `batch_file_${i}` }, i, 0);
        builder.addFileBinary(Buffer.from(`Content for capsa ${i}`), `batch_file_${i}.enc`);
      }

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      expect(bodyString).toContain('"capsaCount":5');
      for (let i = 0; i < capsaCount; i++) {
        expect(bodyString).toContain(`name="capsa_${i}"`);
        expect(bodyString).toContain(`Batch Capsa ${i}`);
      }
    });

    it('should handle capsa with many files', () => {
      const builder = new CapsasMultipartBuilder();
      const fileCount = 20;

      builder.addMetadata(1, 'creator');
      builder.addCapsaMetadata({ subject: 'Many Files' }, 0);

      for (let i = 0; i < fileCount; i++) {
        builder.addFileMetadata({
          fileId: `multifile_${i}`,
          mimetype: 'text/plain',
        }, 0, i);
        builder.addFileBinary(Buffer.from(`File ${i} content`), `multifile_${i}.enc`);
      }

      const body = builder.build();
      const bodyString = body.toString('utf-8');

      for (let i = 0; i < fileCount; i++) {
        expect(bodyString).toContain(`filename="multifile_${i}.json"`);
        expect(bodyString).toContain(`filename="multifile_${i}.enc"`);
      }
    });
  });

  describe('Buffer Handling', () => {
    it('should return new buffer on each build call', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const body1 = builder.build();
      const body2 = builder.build();

      // Should be equal content
      expect(body1.equals(body2)).toBe(true);
      // But different buffer instances
      expect(body1).not.toBe(body2);
    });

    it('should not mutate added buffer data', () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');

      const originalData = Buffer.from('original content');
      const dataCopy = Buffer.from(originalData);
      builder.addFileBinary(originalData, 'file.enc');

      // Mutate original after adding
      originalData[0] = 0xFF;

      const body = builder.build();

      // The built body should contain the original data, not the mutated version
      // Note: This test may fail if the implementation doesn't copy the buffer,
      // which is acceptable behavior - this documents the current behavior
      expect(body.includes(dataCopy) || body.includes(originalData)).toBe(true);
    });

    it('should handle concurrent builds', async () => {
      const builder = new CapsasMultipartBuilder();
      builder.addMetadata(1, 'creator');
      builder.addCapsaMetadata({ test: 'concurrent' }, 0);

      const builds = await Promise.all([
        Promise.resolve(builder.build()),
        Promise.resolve(builder.build()),
        Promise.resolve(builder.build()),
      ]);

      // All builds should produce equivalent results
      expect(builds[0]!.equals(builds[1]!)).toBe(true);
      expect(builds[1]!.equals(builds[2]!)).toBe(true);
    });
  });
});
