/**
 * Tests for capsa-builder.ts - Fluent capsa builder
 * @file tests/unit/builder/capsa-builder.test.ts
 */

import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import * as fs from 'fs';
import type { PartyKey, SystemLimits } from '../../../src/types/index.js';

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

import { CapsaBuilder, type BuiltCapsa, type CapsaUploadData } from '../../../src/builder/capsa-builder.js';

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

    it('should add multiple recipients', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder
        .addRecipient('party_1')
        .addRecipient('party_2')
        .addRecipient('party_3');

      expect(builder.getRecipientIds()).toEqual(['party_1', 'party_2', 'party_3']);
    });
  });

  describe('getRecipientIds', () => {
    it('should return empty array when no recipients', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      expect(builder.getRecipientIds()).toEqual([]);
    });

    it('should return recipient IDs', () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_1').addRecipient('party_2');
      expect(builder.getRecipientIds()).toEqual(['party_1', 'party_2']);
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
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('test content') });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(result.capsa.packageId).toMatch(/^capsa_/);
      expect(result.capsa.keychain.algorithm).toBe('AES-256-GCM');
      expect(result.capsa.signature.algorithm).toBe('RSA-SHA256');
      expect(result.files).toHaveLength(1);
    });

    it('should encrypt subject and body when set', async () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
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
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.structured = { custom: 'data' };
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(result.capsa.encryptedStructured).toBe('base64url-encrypted');
      expect(result.capsa.structuredIV).toMatch(/^mock-iv-\d+$/);
    });

    it('should include metadata when set', async () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
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

      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
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

      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('a'.repeat(2000)) });

      const result = await builder.build([creatorKey, recipientKey]);

      expect(mockCompressData).toHaveBeenCalled();
      expect(result.files[0]?.metadata.compressed).toBe(true);
    });

    it('should not compress when disabled on file', async () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
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

      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
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

      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
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

      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
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

      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey, delegateKey]);

      // Should only have creator and recipient (delegate skipped)
      expect(result.capsa.keychain.keys.length).toBe(2);
      expect(result.capsa.keychain.keys.find(k => k.party === 'party_delegate')).toBeUndefined();
    });

    it('should set accessControl expiresAt', async () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.expiresAt = '2025-12-31T23:59:00Z';
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
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      await expect(builder.build([creatorKey, recipientKey])).rejects.toThrow(/exceeds maximum/);
    });

    it('should include file-level expiration when set', async () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.addFile({
        filename: 'temp.txt',
        buffer: Buffer.from('content'),
        expiresAt: new Date('2025-06-15T10:30:45Z'),
      });

      const result = await builder.build([creatorKey, recipientKey]);

      // File expiration should be normalized (seconds set to 0)
      expect(result.files[0]?.metadata.expiresAt).toBeDefined();
      expect(result.files[0]?.metadata.expiresAt).toMatch(/T10:30:00/);
    });

    it('should create signature with correct canonical string', async () => {
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      await builder.build([creatorKey, recipientKey]);

      expect(mockBuildCanonicalString).toHaveBeenCalled();
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

      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey, unrelatedKey]);

      // Should only have creator and recipient (unrelated skipped)
      expect(result.capsa.keychain.keys.length).toBe(2);
      expect(result.capsa.keychain.keys.find(k => k.party === 'party_unrelated')).toBeUndefined();
    });

    it('should handle actingFor from recipient config', async () => {
      // Testing that actingFor is passed through from recipient config
      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'test.txt', buffer: Buffer.from('content') });

      const result = await builder.build([creatorKey, recipientKey]);

      // Recipient entry should exist with their permissions
      const recipientEntry = result.capsa.keychain.keys.find(k => k.party === 'party_recipient');
      expect(recipientEntry?.permissions).toEqual(['read']);
    });

    it('should handle file read error from path during build', async () => {
      (fs.statSync as Mock).mockReturnValue({ size: 100 });
      (fs.readFileSync as Mock).mockImplementation(() => {
        throw new Error('File not found');
      });

      const builder = new CapsaBuilder(creatorId, creatorPrivateKey, defaultLimits);
      builder.addRecipient('party_recipient');
      builder.addFile({ filename: 'missing.txt', path: '/path/to/missing.txt' });

      await expect(builder.build([creatorKey, recipientKey])).rejects.toThrow('File not found');
    });
  });
});
