/**
 * Tests for capsa-builder.ts - Fluent capsa builder
 * @file tests/unit/builder/capsa-builder.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import * as fs from 'fs';
import type { FileInput, PartyKey, SystemLimits } from '../../../src/types/index.js';

// Use vi.hoisted for mock functions
const {
  mockGenerateMasterKey,
  mockGenerateIV,
  mockEncryptAES,
  mockEncryptAESRaw,
  mockEncryptMasterKeyForParty,
  mockComputeHash,
  mockBuildCanonicalString,
  mockCreateCapsaSignature,
  mockCompressData,
  mockShouldCompress,
  mockGenerateId,
  mockLookupMimeType,
} = vi.hoisted(() => ({
  mockGenerateMasterKey: vi.fn(),
  mockGenerateIV: vi.fn(),
  mockEncryptAES: vi.fn(),
  mockEncryptAESRaw: vi.fn(),
  mockEncryptMasterKeyForParty: vi.fn(),
  mockComputeHash: vi.fn(),
  mockBuildCanonicalString: vi.fn(),
  mockCreateCapsaSignature: vi.fn(),
  mockCompressData: vi.fn(),
  mockShouldCompress: vi.fn(),
  mockGenerateId: vi.fn(),
  mockLookupMimeType: vi.fn(),
}));

// Mock fs
vi.mock('fs', () => ({
  statSync: vi.fn(),
  readFileSync: vi.fn(),
}));

// Mock crypto primitives
vi.mock('../../../src/internal/crypto/primitives.js', () => ({
  generateMasterKey: mockGenerateMasterKey,
  generateIV: mockGenerateIV,
  encryptAES: mockEncryptAES,
  encryptAESRaw: mockEncryptAESRaw,
  encryptMasterKeyForParty: mockEncryptMasterKeyForParty,
  computeHash: mockComputeHash,
}));

// Mock signatures
vi.mock('../../../src/internal/crypto/signatures.js', () => ({
  buildCanonicalString: mockBuildCanonicalString,
  createCapsaSignature: mockCreateCapsaSignature,
}));

vi.mock('../../../src/internal/crypto/key-generator.js', () => ({
  calculatePrivateKeyFingerprint: vi.fn(() => 'fp_creator_key'),
}));

// Mock compression
vi.mock('../../../src/internal/crypto/compression.js', () => ({
  compressData: mockCompressData,
  shouldCompress: mockShouldCompress,
}));

// Mock id generator
vi.mock('../../../src/internal/utils/id-generator.js', () => ({
  generateId: mockGenerateId,
}));

// Mock mimetype lookup
vi.mock('../../../src/internal/utils/mimetype-lookup.js', () => ({
  lookupMimeType: mockLookupMimeType,
}));

import { CapsaBuilder } from '../../../src/builder/capsa-builder.js';

describe('CapsaBuilder', () => {
  const defaultLimits: SystemLimits = {
    maxFileSize: 50 * 1024 * 1024, // 50MB
    maxFilesPerCapsa: 100,
    maxTotalSize: 500 * 1024 * 1024, // 500MB
  };

  const creatorId = 'party_creator';
  const creatorPrivateKey = '-----BEGIN PRIVATE KEY-----\nCreatorPrivate\n-----END PRIVATE KEY-----';
  const masterKeyBuffer = Buffer.from('master-key-32-bytes-for-testing!', 'utf-8');

  // Shared counter ensures every IV is globally unique (satisfies duplicate IV check)
  let ivCounter: number;

  beforeEach(() => {
    vi.clearAllMocks();
    ivCounter = 0;

    // Default mock implementations
    mockGenerateMasterKey.mockReturnValue(masterKeyBuffer);
    mockGenerateIV.mockImplementation(() => `mock-iv-${ivCounter++}`);
    mockGenerateId.mockReturnValue('generated-id-12345');
    mockLookupMimeType.mockReturnValue('application/octet-stream');
    mockShouldCompress.mockReturnValue(false);
    mockComputeHash.mockReturnValue('sha256-hash');
    mockBuildCanonicalString.mockReturnValue('canonical-string');
    mockCreateCapsaSignature.mockReturnValue({
      algorithm: 'RSA-SHA256',
      protected: 'base64-protected',
      payload: 'base64-payload',
      signature: 'base64-signature',
    });
    mockEncryptAES.mockImplementation(() => ({
      encryptedData: 'base64url-encrypted',
      iv: `mock-iv-${ivCounter++}`,
      authTag: 'base64url-auth-tag',
    }));
    mockEncryptAESRaw.mockImplementation(() => ({
      encryptedData: Buffer.from('raw-encrypted-content'),
      iv: Buffer.from(`rawiv-${ivCounter++}--`),
      authTag: Buffer.from('rawauthtagbytes!'),
    }));
    mockEncryptMasterKeyForParty.mockReturnValue('encrypted-master-key-for-party');
  });

  describe('constructor', () => {
    it('should create builder with creator info and limits', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      expect(builder).toBeInstanceOf(CapsaBuilder);
      expect(mockGenerateMasterKey).toHaveBeenCalled();
    });
  });

  describe('addRecipient', () => {
    it('should add recipient and return this for chaining', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      const result = builder.addRecipient('party_recipient');
      expect(result).toBe(builder);
    });

    it('should reject a second recipient', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_1');

      expect(() => builder.addRecipient('party_2')).toThrow(
        /already has a recipient \("party_1"\).*exactly one recipient.*one builder per recipient/s
      );
      expect(builder.getRecipientIds()).toEqual(['party_1']);
    });

    it('should reject adding the same recipient twice', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_1');

      expect(() => builder.addRecipient('party_1')).toThrow(/already has a recipient/);
    });

    it('should not offer addRecipients', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      expect((builder as unknown as Record<string, unknown>)['addRecipients']).toBeUndefined();
    });
  });

  describe('getRecipientIds', () => {
    it('should return empty array when no recipients', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      expect(builder.getRecipientIds()).toEqual([]);
    });

    it('should return the recipient ID', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_1');
      expect(builder.getRecipientIds()).toEqual(['party_1']);
    });
  });

  describe('addFile', () => {
    it('should add file from buffer', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      const result = builder.addFile({
        filename: 'test.txt',
        buffer: Buffer.from('test content'),
      });
      expect(result).toBe(builder);
      expect(builder.getFileCount()).toBe(1);
    });

    it('should add file from path', () => {
      (fs.statSync as Mock).mockReturnValue({ size: 1024 });

      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      const result = builder.addFile({
        filename: 'document.pdf',
        path: '/path/to/document.pdf',
      });
      expect(result).toBe(builder);
      expect(builder.getFileCount()).toBe(1);
    });

    it('should throw if file exceeds size limit', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      const largeBuffer = Buffer.alloc(60 * 1024 * 1024); // 60MB

      expect(() =>
        builder.addFile({
          filename: 'large.bin',
          buffer: largeBuffer,
        })
      ).toThrow(/exceeds maximum size/);
    });

    it('should throw if file count exceeds limit', () => {
      const limitedLimits: SystemLimits = { ...defaultLimits, maxFilesPerCapsa: 2 };
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, limitedLimits);

      builder.addFile({ filename: 'file1.txt', buffer: Buffer.from('1') });
      builder.addFile({ filename: 'file2.txt', buffer: Buffer.from('2') });

      expect(() =>
        builder.addFile({ filename: 'file3.txt', buffer: Buffer.from('3') })
      ).toThrow(/already has 2 files/);
    });

    it('should throw if file has neither path nor buffer', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      expect(() =>
        builder.addFile({ filename: 'invalid.txt' } as any)
      ).toThrow(/must have either path or buffer/);
    });
  });

  describe('caller errors are VALIDATION_ERROR', () => {
    const validation = expect.objectContaining({ name: 'CapsaraError', code: 'VALIDATION_ERROR', statusCode: 0 });

    function builder(limits: SystemLimits = defaultLimits): CapsaBuilder {
      return new CapsaBuilder(creatorId, creatorPrivateKey, limits);
    }

    it('rejects an empty recipient id', () => {
      expect(() => builder().addRecipient('')).toThrow(validation);
    });

    it('rejects a recipient id over 100 characters but accepts exactly 100', () => {
      expect(() => builder().addRecipient('p'.repeat(101))).toThrow(validation);
      expect(() => builder().addRecipient('p'.repeat(100))).not.toThrow();
    });

    it('rejects a second recipient', () => {
      const b = builder().addRecipient('party_1');
      expect(() => b.addRecipient('party_2')).toThrow(validation);
    });

    it('rejects a file over the size limit', () => {
      expect(() => builder().addFile({ filename: 'big.bin', buffer: Buffer.alloc(defaultLimits.maxFileSize + 1) })).toThrow(validation);
    });

    it('rejects a file beyond the file count limit', () => {
      const b = builder({ ...defaultLimits, maxFilesPerCapsa: 1 }).addFile({ filename: 'a', buffer: Buffer.from('a') });
      expect(() => b.addFile({ filename: 'b', buffer: Buffer.from('b') })).toThrow(validation);
    });

    it('rejects a file with neither path nor buffer', () => {
      expect(() => builder().addFile({ filename: 'x' } as FileInput)).toThrow(validation);
    });

    it('rejects a file path that cannot be read', () => {
      (fs.statSync as Mock).mockImplementationOnce(() => {
        throw new Error("ENOENT: no such file or directory, stat '/missing.pdf'");
      });

      expect(() => builder().addFile({ filename: 'missing.pdf', path: '/missing.pdf' })).toThrow(
        expect.objectContaining({ code: 'VALIDATION_ERROR', statusCode: 0, message: expect.stringContaining('ENOENT') })
      );
    });

    it('rejects an invalid expiration date', () => {
      expect(() => builder().withExpiration('not a date')).toThrow(validation);
      expect(() => builder().withExpiration(new Date(Number.NaN))).toThrow(validation);
    });

    it('does not change the caller\'s Date when rounding the expiration', () => {
      const date = new Date('2030-01-01T10:20:30.400Z');
      const b = builder().withExpiration(date);
      expect(date.toISOString()).toBe('2030-01-01T10:20:30.400Z');
      expect(b.expiresAt?.toISOString()).toBe('2030-01-01T10:20:00.000Z');
    });
  });

  describe('getFileCount', () => {
    it('should return 0 when no files', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      expect(builder.getFileCount()).toBe(0);
    });

    it('should return correct count after adding files', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addFile({ filename: 'file1.txt', buffer: Buffer.from('1') });
      builder.addFile({ filename: 'file2.txt', buffer: Buffer.from('2') });
      expect(builder.getFileCount()).toBe(2);
    });
  });

  describe('expiresAt property', () => {
    it('should set and get expiration date', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      const expDate = new Date('2025-12-31T23:59:30.500Z');
      builder.expiresAt = expDate;

      // Should be normalized (seconds/ms set to 0)
      const result = builder.expiresAt;
      expect(result?.getSeconds()).toBe(0);
      expect(result?.getMilliseconds()).toBe(0);
    });

    it('should accept string date', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.expiresAt = '2025-06-15T10:30:45Z';

      const result = builder.expiresAt;
      expect(result).toBeInstanceOf(Date);
      expect(result?.getSeconds()).toBe(0);
    });

    it('should return undefined when not set', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      expect(builder.expiresAt).toBeUndefined();
    });

    it('should allow clearing expiration', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.expiresAt = new Date();
      builder.expiresAt = undefined;
      expect(builder.expiresAt).toBeUndefined();
    });
  });

  describe('subject and body properties', () => {
    it('should allow setting subject', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.subject = 'Test Subject';
      expect(builder.subject).toBe('Test Subject');
    });

    it('should allow setting body', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.body = 'This is the body content';
      expect(builder.body).toBe('This is the body content');
    });
  });

  describe('structured property', () => {
    it('should allow setting structured data', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.structured = { key: 'value', nested: { data: 123 } };
      expect(builder.structured).toEqual({ key: 'value', nested: { data: 123 } });
    });
  });

  describe('metadata property', () => {
    it('should allow setting metadata fields', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.metadata.label = 'Important Document';
      builder.metadata.tags = ['urgent', 'legal'];
      builder.metadata.notes = 'Please review';

      expect(builder.metadata.label).toBe('Important Document');
      expect(builder.metadata.tags).toEqual(['urgent', 'legal']);
    });
  });

  describe('build', () => {
    /**
     * Builder with an expiration already set.
     * build() requires one — retention is a per-record decision with no safe default —
     * so every build test needs it, and these tests are not about that rule.
     */
    const makeBuildableBuilder = () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.expiresAt = '2027-12-31T23:59:00Z';
      return builder;
    };

    const creatorKey: PartyKey = {
      id: 'party_creator',
      publicKey: '-----BEGIN PUBLIC KEY-----\nCreatorPubKey\n-----END PUBLIC KEY-----',
      fingerprint: 'SHA256:creator',
    };

    const recipientKey: PartyKey = {
      id: 'party_recipient',
      publicKey: '-----BEGIN PUBLIC KEY-----\nRecipientPubKey\n-----END PUBLIC KEY-----',
      fingerprint: 'SHA256:recipient',
    };

    beforeEach(() => {
      (fs.readFileSync as Mock).mockReturnValue(Buffer.from('file content'));
      (fs.statSync as Mock).mockReturnValue({ size: 100 });
    });

    it('should build capsa with files', async () => {
      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('test content') });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(result.capsa.packageId).toMatch(/^capsa_/);
      expect(result.capsa.keychain.algorithm).toBe('AES-256-GCM');
      expect(result.capsa.signature.algorithm).toBe('RSA-SHA256');
      expect(result.files).toHaveLength(1);
    });

    it('should encrypt subject and body when set', async () => {
      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.subject = 'Test Subject';
      builder.body = 'Test Body';
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(result.capsa.encryptedSubject).toBe('base64url-encrypted');
      expect(result.capsa.subjectIV).toMatch(/^mock-iv-\d+$/);
      expect(result.capsa.encryptedBody).toBe('base64url-encrypted');
      expect(result.capsa.bodyIV).toMatch(/^mock-iv-\d+$/);
    });

    it('should encrypt structured data when set', async () => {
      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.structured = { custom: 'data' };
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(result.capsa.encryptedStructured).toBe('base64url-encrypted');
      expect(result.capsa.structuredIV).toMatch(/^mock-iv-\d+$/);
    });

    it('should include metadata when set', async () => {
      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.metadata.label = 'Test Label';
      builder.metadata.tags = ['tag1'];
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(result.capsa.metadata?.label).toBe('Test Label');
      expect(result.capsa.metadata?.tags).toEqual(['tag1']);
    });

    it('should handle file from path', async () => {
      (fs.statSync as Mock).mockReturnValue({ size: 500 });
      (fs.readFileSync as Mock).mockReturnValue(Buffer.from('file from disk'));

      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'doc.pdf', path: '/path/to/doc.pdf' });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(fs.readFileSync).toHaveBeenCalledWith('/path/to/doc.pdf');
      expect(result.files).toHaveLength(1);
    });

    it('should compress files when appropriate', async () => {
      mockShouldCompress.mockReturnValue(true);
      mockCompressData.mockResolvedValue({
        compressedData: Buffer.from('compressed'),
        algorithm: 'gzip',
      });

      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('a'.repeat(2000)) });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(mockCompressData).toHaveBeenCalled();
      expect(result.files[0]?.metadata.compressed).toBe(true);
    });

    it('should not compress when disabled on file', async () => {
      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({
        filename: 'test.txt',
        buffer: Buffer.from('content'),
        compress: false,
      });

      await builder.build([creatorKey, recipientKey]);

      expect(mockCompressData).not.toHaveBeenCalled();
    });

    it('should use provided mimetype over lookup', async () => {
      mockLookupMimeType.mockReturnValue('text/plain');

      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({
        filename: 'test.txt',
        buffer: Buffer.from('content'),
        mimetype: 'application/custom',
      });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(result.files[0]?.metadata.mimetype).toBe('application/custom');
    });

    it('should look up mimetype from path when not provided', async () => {
      mockLookupMimeType.mockReturnValue('application/pdf');
      (fs.statSync as Mock).mockReturnValue({ size: 100 });
      (fs.readFileSync as Mock).mockReturnValue(Buffer.from('pdf content'));

      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({
        filename: 'document.pdf',
        path: '/path/to/document.pdf',
      });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(mockLookupMimeType).toHaveBeenCalledWith('/path/to/document.pdf');
      expect(result.files[0]?.metadata.mimetype).toBe('application/pdf');
    });

    it('should include delegates in keychain', async () => {
      const delegateKey: PartyKey = {
        id: 'party_delegate',
        publicKey: '-----BEGIN PUBLIC KEY-----\nDelegatePubKey\n-----END PUBLIC KEY-----',
        fingerprint: 'SHA256:delegate',
        isDelegate: ['party_recipient'], // Delegate for recipient
      };

      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey, delegateKey]);

      // Should have creator, recipient, and delegate
      expect(result.capsa.keychain.keys.length).toBe(3);

      const delegateEntry = result.capsa.keychain.keys.find(k => k.party === 'party_delegate');
      expect(delegateEntry?.permissions).toEqual(['delegate']);
      expect(delegateEntry?.actingFor).toEqual(['party_recipient']);
    });

    it('should skip delegates not acting for this capsa recipients', async () => {
      const delegateKey: PartyKey = {
        id: 'party_delegate',
        publicKey: '-----BEGIN PUBLIC KEY-----\nDelegatePubKey\n-----END PUBLIC KEY-----',
        fingerprint: 'SHA256:delegate',
        isDelegate: ['party_other'], // Delegate for someone NOT in this capsa
      };

      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey, delegateKey]);

      // Should only have creator and recipient (delegate skipped)
      expect(result.capsa.keychain.keys.length).toBe(2);
      expect(result.capsa.keychain.keys.find(k => k.party === 'party_delegate')).toBeUndefined();
    });

    it('should set accessControl expiresAt', async () => {
      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(result.capsa.accessControl.expiresAt).toBeDefined();
    });

    it('should throw if total size exceeds limit', async () => {
      const smallLimits: SystemLimits = { ...defaultLimits, maxTotalSize: 100 };

      // Mock encrypted data larger than limit (encryptAESRaw is used for files)
      mockEncryptAESRaw.mockReturnValue({
        encryptedData: Buffer.alloc(200), // > 100 bytes
        iv: Buffer.from('rawiv12bytes'),
        authTag: Buffer.from('rawauthtagbytes!'),
      });

      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, smallLimits);
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      await expect(builder.build([creatorKey, recipientKey])).rejects.toThrow(/exceeds maximum/);
    });

    it('should require an expiration', async () => {
      // Retention depends on the record — months for a claim, years for driver
      // records — so there is no default that would be right often enough to have one
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      await expect(builder.build([creatorKey, recipientKey]))
        .rejects.toThrow(/Expiration is required/);
    });

    it('should name withExpiration in the error so the fix is obvious', async () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      await expect(builder.build([creatorKey, recipientKey]))
        .rejects.toThrow(/withExpiration\(\)/);
    });

    describe('build refusals are BUILD_FAILED with a reason', () => {
      function buildFailed(reason: string) {
        return expect.objectContaining({ name: 'CapsaraError', code: 'BUILD_FAILED', statusCode: 0, details: { reason } });
      }

      it('reports a missing expiration as EXPIRATION_REQUIRED', async () => {
        const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits)
          .addRecipient('party_recipient')
          .addFile({ filename: 'a.txt', buffer: Buffer.from('a') });

        await expect(builder.build([creatorKey, recipientKey])).rejects.toEqual(buildFailed('EXPIRATION_REQUIRED'));
      });

      it('reports a missing recipient as NO_RECIPIENT', async () => {
        const builder = makeBuildableBuilder().addFile({ filename: 'a.txt', buffer: Buffer.from('a') });

        await expect(builder.build([creatorKey, recipientKey])).rejects.toEqual(buildFailed('NO_RECIPIENT'));
      });

      it('reports no files and no message as NO_CONTENT', async () => {
        const builder = makeBuildableBuilder().addRecipient('party_recipient');

        await expect(builder.build([creatorKey, recipientKey])).rejects.toEqual(buildFailed('NO_CONTENT'));
      });

      it('reports an empty file as EMPTY_FILE', async () => {
        const builder = makeBuildableBuilder().addRecipient('party_recipient').addFile({ filename: 'e.txt', buffer: Buffer.alloc(0) });

        await expect(builder.build([creatorKey, recipientKey])).rejects.toEqual(buildFailed('EMPTY_FILE'));
      });

      it('reports a file path that cannot be read at build time as FILE_READ_FAILED', async () => {
        (fs.statSync as Mock).mockReturnValue({ size: 10 });
        (fs.readFileSync as Mock).mockImplementationOnce(() => {
          throw new Error('EACCES: permission denied');
        });
        const builder = makeBuildableBuilder().addRecipient('party_recipient').addFile({ filename: 'x.pdf', path: '/x.pdf' });

        await expect(builder.build([creatorKey, recipientKey])).rejects.toEqual(buildFailed('FILE_READ_FAILED'));
      });

      it('reports the total size limit as TOTAL_SIZE_EXCEEDED', async () => {
        mockEncryptAESRaw.mockReturnValue({
          encryptedData: Buffer.alloc(200),
          iv: Buffer.from('rawiv12bytes'),
          authTag: Buffer.from('rawauthtagbytes!'),
        });
        const builder = new CapsaBuilder(creatorId, creatorPrivateKey, { ...defaultLimits, maxTotalSize: 100 })
          .withExpiration('2027-12-31T23:59:00Z')
          .addRecipient('party_recipient')
          .addFile({ filename: 'a.txt', buffer: Buffer.from('a') });

        await expect(builder.build([creatorKey, recipientKey])).rejects.toEqual(buildFailed('TOTAL_SIZE_EXCEEDED'));
      });

      it('reports metadata over the limits with a specific reason', async () => {
        const cases: Array<[string, (b: CapsaBuilder) => void]> = [
          ['METADATA_LABEL_TOO_LONG', (b) => { b.metadata.label = 'l'.repeat(513); }],
          ['TOO_MANY_TAGS', (b) => { b.metadata.tags = Array.from({ length: 101 }, (_, i) => `t${i}`); }],
          ['TAG_TOO_LONG', (b) => { b.metadata.tags = ['t'.repeat(101)]; }],
          ['METADATA_NOTES_TOO_LONG', (b) => { b.metadata.notes = 'n'.repeat(10_241); }],
          ['TOO_MANY_RELATED_PACKAGES', (b) => { b.metadata.relatedPackages = Array.from({ length: 51 }, (_, i) => `p${i}`); }],
        ];

        for (const [reason, apply] of cases) {
          const builder = makeBuildableBuilder().addRecipient('party_recipient').addFile({ filename: 'a.txt', buffer: Buffer.from('a') });
          apply(builder);
          await expect(builder.build([creatorKey, recipientKey])).rejects.toEqual(buildFailed(reason));
        }
      });

      describe('expiration window', () => {
        const NOW = Date.parse('2026-11-09T12:00:30.000Z');
        const DAY = 24 * 60 * 60 * 1000;

        beforeEach(() => {
          vi.useFakeTimers({ toFake: ['Date'] });
          vi.setSystemTime(NOW);
        });

        afterEach(() => {
          vi.useRealTimers();
        });

        function builderWith(limits: SystemLimits, capsaExpiry: string, fileExpiry?: string | Date): CapsaBuilder {
          return new CapsaBuilder(creatorId, creatorPrivateKey, limits)
            .withExpiration(capsaExpiry)
            .addRecipient('party_recipient')
            .addFile({ filename: 'a.txt', buffer: Buffer.from('a'), ...(fileExpiry !== undefined && { expiresAt: fileExpiry }) });
        }

        const iso = (ms: number) => new Date(ms).toISOString();

        it('rejects a capsa expiration in the past or at the current minute', async () => {
          await expect(builderWith(defaultLimits, '2026-11-08T12:00:00Z').build([creatorKey, recipientKey]))
            .rejects.toEqual(buildFailed('EXPIRATION_IN_PAST'));
          await expect(builderWith(defaultLimits, '2026-11-09T12:00:45Z').build([creatorKey, recipientKey]))
            .rejects.toEqual(buildFailed('EXPIRATION_IN_PAST'));
        });

        it('accepts a capsa expiring in the next minute', async () => {
          await expect(builderWith(defaultLimits, '2026-11-09T12:01:00Z').build([creatorKey, recipientKey])).resolves.toBeDefined();
        });

        it('rejects a capsa expiration more than 3650 days ahead when limits give none', async () => {
          const error = await builderWith(defaultLimits, iso(NOW + 3651 * DAY)).build([creatorKey, recipientKey]).catch((e: unknown) => e);

          expect(error).toEqual(buildFailed('EXPIRATION_TOO_FAR'));
          expect((error as Error).message).toContain('more than 3650 days in the future');
        });

        it('accepts a capsa expiration exactly at the limit', async () => {
          await expect(builderWith(defaultLimits, iso(NOW + 3650 * DAY)).build([creatorKey, recipientKey])).resolves.toBeDefined();
        });

        it('uses maxExpirationDays from limits', async () => {
          const limits = { ...defaultLimits, maxExpirationDays: 30 };

          await expect(builderWith(limits, iso(NOW + 31 * DAY)).build([creatorKey, recipientKey]))
            .rejects.toEqual(buildFailed('EXPIRATION_TOO_FAR'));
          await expect(builderWith(limits, iso(NOW + 29 * DAY)).build([creatorKey, recipientKey])).resolves.toBeDefined();
        });

        it.each([0, -5, Number.NaN])('falls back to 3650 days when maxExpirationDays is %s', async (value) => {
          const limits = { ...defaultLimits, maxExpirationDays: value };

          await expect(builderWith(limits, iso(NOW + 3000 * DAY)).build([creatorKey, recipientKey])).resolves.toBeDefined();
          await expect(builderWith(limits, iso(NOW + 3651 * DAY)).build([creatorKey, recipientKey]))
            .rejects.toEqual(buildFailed('EXPIRATION_TOO_FAR'));
        });

        it('rejects a file expiration in the past', async () => {
          await expect(builderWith(defaultLimits, iso(NOW + 10 * DAY), '2026-01-01T00:00:00Z').build([creatorKey, recipientKey]))
            .rejects.toEqual(buildFailed('FILE_EXPIRATION_IN_PAST'));
        });

        it('rejects a file expiration beyond the limit before the outlives-capsa check', async () => {
          const limits = { ...defaultLimits, maxExpirationDays: 30 };

          await expect(builderWith(limits, iso(NOW + 10 * DAY), iso(NOW + 40 * DAY)).build([creatorKey, recipientKey]))
            .rejects.toEqual(buildFailed('FILE_EXPIRATION_TOO_FAR'));
        });

        it('rejects an invalid file expiration date', async () => {
          await expect(builderWith(defaultLimits, iso(NOW + 10 * DAY), 'not a date').build([creatorKey, recipientKey]))
            .rejects.toEqual(buildFailed('INVALID_FILE_EXPIRATION'));
        });

        it('accepts a valid file expiration without changing the caller\'s Date', async () => {
          const fileDate = new Date(NOW + 5 * DAY + 45_000);
          const before = fileDate.toISOString();

          const built = await builderWith(defaultLimits, iso(NOW + 10 * DAY), fileDate).build([creatorKey, recipientKey]);

          expect(built.files[0]?.metadata.expiresAt).toMatch(/:00\.000Z$/);
          expect(fileDate.toISOString()).toBe(before);
        });
      });

      it('keeps RECIPIENT_KEY_NOT_FOUND as its own code', async () => {
        const builder = makeBuildableBuilder().addRecipient('party_recipient').addFile({ filename: 'a.txt', buffer: Buffer.from('a') });

        await expect(builder.build([creatorKey])).rejects.toMatchObject({ code: 'RECIPIENT_KEY_NOT_FOUND' });
      });
    });

    it('should include file-level expiration when set', async () => {
      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({
        filename: 'temp.txt',
        buffer: Buffer.from('content'),
        expiresAt: new Date('2027-06-15T10:30:45Z'),
      });

      const result = await builder.build([creatorKey, recipientKey]);

      // File expiration should be normalized (seconds set to 0)
      expect(result.files[0]?.metadata.expiresAt).toBeDefined();
      expect(result.files[0]?.metadata.expiresAt).toMatch(/T10:30:00/);
    });

    it('should create signature with correct canonical string', async () => {
      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      await builder.build([creatorKey, recipientKey]);

      expect(mockBuildCanonicalString).toHaveBeenCalledWith(expect.objectContaining({
        creatorPartyId: creatorId,
        creatorKeyFingerprint: 'fp_creator_key',
      }));
      expect(mockCreateCapsaSignature).toHaveBeenCalledWith(
        'canonical-string',
        creatorPrivateKey
      );
    });

    it('should skip unrelated party keys (not creator, recipient, or delegate)', async () => {
      const unrelatedKey: PartyKey = {
        id: 'party_unrelated',
        publicKey: '-----BEGIN PUBLIC KEY-----\nUnrelatedPubKey\n-----END PUBLIC KEY-----',
        fingerprint: 'SHA256:unrelated',
      };

      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey, unrelatedKey]);

      // Should only have creator and recipient (unrelated skipped)
      expect(result.capsa.keychain.keys.length).toBe(2);
      expect(result.capsa.keychain.keys.find(k => k.party === 'party_unrelated')).toBeUndefined();
    });

    it('should handle actingFor from recipient config', async () => {
      // Testing that actingFor is passed through from recipient config
      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey]);

      // Recipient entry should exist with their permissions
      const recipientEntry = result.capsa.keychain.keys.find(k => k.party === 'party_recipient');
      expect(recipientEntry?.permissions).toEqual(['read']);
    });

    describe('one principal per capsa', () => {
      const delegateKey = (id: string, actsFor: string[]): PartyKey => ({
        id,
        publicKey: `-----BEGIN PUBLIC KEY-----\n${id}\n-----END PUBLIC KEY-----`,
        fingerprint: `SHA256:${id}`,
        isDelegate: actsFor,
      });

      it('should reject build with no recipient before encrypting anything', async () => {
        const builder = makeBuildableBuilder();
        builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

        await expect(builder.build([creatorKey, recipientKey])).rejects.toThrow(
          'Capsa has no recipient. Call addRecipient() with the party this capsa is sent to.'
        );
        expect(mockEncryptAESRaw).not.toHaveBeenCalled();
      });

      it('should scope a delegate to the principal even when it acts for other parties', async () => {
        const builder = makeBuildableBuilder();
        builder.addRecipient('party_recipient');
        builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

        const result = await builder.build([
          creatorKey,
          recipientKey,
          delegateKey('party_shared_delegate', ['party_other', 'party_recipient']),
          delegateKey('party_other_delegate', ['party_other']),
          delegateKey('party_creator_delegate', [creatorId]),
        ]);

        const keys = result.capsa.keychain.keys;
        expect(keys.map(k => k.party).sort()).toEqual(
          ['party_creator', 'party_recipient', 'party_shared_delegate'].sort()
        );
        expect(keys.find(k => k.party === 'party_shared_delegate')?.actingFor).toEqual(['party_recipient']);
      });

      it('should treat the principal as the principal even if it is a delegate of another party', async () => {
        const builder = makeBuildableBuilder();
        builder.addRecipient('party_recipient');
        builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

        const result = await builder.build([
          creatorKey,
          { ...recipientKey, isDelegate: ['party_other'] },
        ]);

        const entry = result.capsa.keychain.keys.find(k => k.party === 'party_recipient');
        expect(entry?.permissions).toEqual(['read']);
        expect(entry?.actingFor).toBeUndefined();
        expect(entry?.encryptedKey).toBe('encrypted-master-key-for-party');
      });

      it('should build a valid keychain for a principal and its delegates', async () => {
        const builder = makeBuildableBuilder();
        builder.addRecipient('party_recipient');
        builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

        const result = await builder.build([
          creatorKey,
          recipientKey,
          delegateKey('party_ams', ['party_recipient']),
          delegateKey('party_rater', ['party_recipient']),
        ]);

        const keys = result.capsa.keychain.keys;
        // Each party appears once
        expect(new Set(keys.map(k => k.party)).size).toBe(keys.length);
        expect(keys).toHaveLength(4);

        const principalEntry = keys.find(k => k.party === 'party_recipient');
        expect(principalEntry?.encryptedKey).toBeTruthy();
        expect(principalEntry?.actingFor).toBeUndefined();

        const delegates = keys.filter(k => k.actingFor !== undefined);
        expect(delegates.map(k => k.party).sort()).toEqual(['party_ams', 'party_rater']);
        for (const d of delegates) {
          expect(d.permissions).toEqual(['delegate']);
          expect(d.actingFor).toEqual(['party_recipient']);
          expect(d.encryptedKey).toBeTruthy();
        }
      });

      it('should keep each capsa to its own principal when builders share party keys in a batch', async () => {
        // sendCapsas fetches keys once for a whole batch, so each builder sees
        // the other capsas' recipients and delegates too
        const sharedKeys: PartyKey[] = [
          creatorKey,
          recipientKey,
          { id: 'party_vendor', publicKey: 'vendor-pub', fingerprint: 'SHA256:vendor' },
          delegateKey('party_ams', ['party_recipient']),
          delegateKey('party_vendor_system', ['party_vendor']),
          delegateKey('party_shared', ['party_recipient', 'party_vendor']),
        ];

        const toAgent = makeBuildableBuilder().addRecipient('party_recipient');
        toAgent.addFile({ filename: 'a.txt', buffer: Buffer.from('a') });
        const toVendor = makeBuildableBuilder().addRecipient('party_vendor');
        toVendor.addFile({ filename: 'v.txt', buffer: Buffer.from('v') });

        const [agentCapsa, vendorCapsa] = await Promise.all([
          toAgent.build(sharedKeys),
          toVendor.build(sharedKeys),
        ]);

        const summarize = (keys: Array<{ party: string; actingFor?: string[] }>) =>
          Object.fromEntries(keys.map(k => [k.party, k.actingFor ?? null]));

        expect(summarize(agentCapsa!.capsa.keychain.keys)).toEqual({
          party_creator: null,
          party_recipient: null,
          party_ams: ['party_recipient'],
          party_shared: ['party_recipient'],
        });
        expect(summarize(vendorCapsa!.capsa.keychain.keys)).toEqual({
          party_creator: null,
          party_vendor: null,
          party_vendor_system: ['party_vendor'],
          party_shared: ['party_vendor'],
        });
      });

      it('should build a self-send with the creator as principal and its delegates', async () => {
        const builder = makeBuildableBuilder();
        builder.addRecipient(creatorId);
        builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

        const result = await builder.build([
          creatorKey,
          recipientKey,
          delegateKey('party_creator_ams', [creatorId]),
          delegateKey('party_recipient_ams', ['party_recipient']),
        ]);

        const keys = result.capsa.keychain.keys;
        expect(keys.map(k => k.party).sort()).toEqual(['party_creator', 'party_creator_ams']);

        const creatorEntry = keys.find(k => k.party === creatorId);
        expect(creatorEntry?.encryptedKey).toBe('encrypted-master-key-for-party');
        expect(creatorEntry?.actingFor).toBeUndefined();

        const delegateEntry = keys.find(k => k.party === 'party_creator_ams');
        expect(delegateEntry?.permissions).toEqual(['delegate']);
        expect(delegateEntry?.actingFor).toEqual([creatorId]);
        expect(delegateEntry?.encryptedKey).toBeTruthy();
      });

      it('should build a self-send with only the creator when it has no delegates', async () => {
        const builder = makeBuildableBuilder();
        builder.addRecipient(creatorId);
        builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

        const result = await builder.build([creatorKey, recipientKey]);

        const keys = result.capsa.keychain.keys;
        expect(keys).toHaveLength(1);
        expect(keys[0]?.party).toBe(creatorId);
        expect(keys[0]?.encryptedKey).toBe('encrypted-master-key-for-party');
        expect(keys[0]?.actingFor).toBeUndefined();
      });

      it('should allow the creator to be a delegate of the principal', async () => {
        const builder = makeBuildableBuilder();
        builder.addRecipient('party_recipient');
        builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

        const result = await builder.build([
          { ...creatorKey, isDelegate: ['party_recipient'] },
          recipientKey,
        ]);

        const creatorEntry = result.capsa.keychain.keys.find(k => k.party === creatorId);
        expect(creatorEntry?.permissions).toEqual(['delegate']);
        expect(creatorEntry?.actingFor).toEqual(['party_recipient']);
      });

      it('should reject a keychain over the server limit', async () => {
        const builder = makeBuildableBuilder();
        builder.addRecipient('party_recipient');
        builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

        const delegates = Array.from({ length: 99 }, (_, i) => delegateKey(`party_d${i}`, ['party_recipient']));

        await expect(builder.build([creatorKey, recipientKey, ...delegates])).rejects.toThrow(
          /Keychain has 101 entries.*limit of 100/
        );
      });
    });

    it('should handle file read error from path during build', async () => {
      (fs.statSync as Mock).mockReturnValue({ size: 100 });
      (fs.readFileSync as Mock).mockImplementation(() => {
        throw new Error('File not found');
      });

      const builder = makeBuildableBuilder();
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'missing.txt', path: '/path/to/missing.txt' });

      await expect(builder.build([creatorKey, recipientKey])).rejects.toThrow('File not found');
    });
  });
});
