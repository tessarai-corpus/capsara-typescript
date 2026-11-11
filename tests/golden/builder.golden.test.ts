/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - CapsaBuilder
 * Tests master key gen, limits enforcement, IV uniqueness, file size/count validation,
 * expiration normalization, signature generation, compression threshold, delegation keychain.
 * Tests CapsaBuilder directly with real crypto.
 */

import * as crypto from 'crypto';
import { CapsaBuilder, SERVER_LIMITS } from '../../src/builder/capsa-builder.js';
import type { PartyKey, SystemLimits } from '../../src/types/index.js';
import { rsa4096KeyPair } from '../fixtures/rsa-keys.js';

const DEFAULT_LIMITS: SystemLimits = {
  maxFileSize: 100 * 1024 * 1024,      // 100MB
  maxFilesPerCapsa: 500,
  maxTotalSize: 500 * 1024 * 1024,     // 500MB
};

const creatorKeys = rsa4096KeyPair(0);
const recipientKeys = rsa4096KeyPair(1);
const delegateKeys = rsa4096KeyPair(2);

function createFingerprint(publicKey: string): string {
  const der = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

function makePartyKey(id: string, keys: { publicKey: string }, isDelegate?: string[]): PartyKey {
  return {
    id,
    publicKey: keys.publicKey,
    fingerprint: createFingerprint(keys.publicKey),
    isDelegate,
  };
}

describe('Golden: Builder', () => {
  it('should generate a 32-byte master key on construction', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('test'), 'test.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    // The keychain should have an entry for creator
    expect(built.capsa.keychain.keys.length).toBeGreaterThanOrEqual(1);
    // Algorithm should be AES-256-GCM
    expect(built.capsa.keychain.algorithm).toBe('AES-256-GCM');
  });

  it('should fail the build when a recipient public key is PKCS#1 rather than SPKI', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('test'), 'test.txt');

    const pkcs1 = crypto.createPublicKey(recipientKeys.publicKey).export({ type: 'pkcs1', format: 'pem' }).toString();
    const recipient = { ...makePartyKey('recipient_1', recipientKeys), publicKey: pkcs1 };

    await expect(builder.build([makePartyKey('creator_1', creatorKeys), recipient]))
      .rejects.toThrow('publicKeyPEM must be an SPKI PEM public key');
  });

  it('should enforce max files per capsa limit', () => {
    const limits: SystemLimits = { ...DEFAULT_LIMITS, maxFilesPerCapsa: 2 };
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, limits);

    builder.addFileFromBuffer(Buffer.from('a'), 'a.txt');
    builder.addFileFromBuffer(Buffer.from('b'), 'b.txt');

    expect(() => builder.addFileFromBuffer(Buffer.from('c'), 'c.txt')).toThrow(
      /max: 2/
    );
  });

  it('should enforce max file size limit', () => {
    const limits: SystemLimits = { ...DEFAULT_LIMITS, maxFileSize: 10 };
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, limits);

    expect(() =>
      builder.addFileFromBuffer(Buffer.from('x'.repeat(20)), 'big.txt')
    ).toThrow(/exceeds maximum/);
  });

  it('should enforce max total size limit', async () => {
    const limits: SystemLimits = { ...DEFAULT_LIMITS, maxTotalSize: 50, maxFileSize: 100 };
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, limits);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';

    // Each file will be slightly larger after encryption; use enough data to exceed 50 bytes total
    builder.addFileFromBuffer(Buffer.from('x'.repeat(30)), 'a.txt');
    builder.addFileFromBuffer(Buffer.from('x'.repeat(30)), 'b.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    await expect(builder.build(partyKeys)).rejects.toThrow(/exceeds maximum/);
  });

  it('should produce unique IVs for each file within a single build', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('file1'), 'a.txt');
    builder.addFileFromBuffer(Buffer.from('file2'), 'b.txt');
    builder.addFileFromBuffer(Buffer.from('file3'), 'c.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    const ivs = built.capsa.files.map(f => f.iv);
    const uniqueIVs = new Set(ivs);
    expect(uniqueIVs.size).toBe(ivs.length);
  });

  it('should produce unique filename IVs for each file', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('f1'), 'a.txt');
    builder.addFileFromBuffer(Buffer.from('f2'), 'b.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    const filenameIVs = built.capsa.files.map(f => f.filenameIV);
    const unique = new Set(filenameIVs);
    expect(unique.size).toBe(filenameIVs.length);
  });

  it('should normalize expiration date by zeroing seconds', () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.withExpiration(new Date('2025-12-01T10:30:45.123Z'));

    const exp = builder.expiresAt;
    expect(exp).toBeDefined();
    expect(exp!.getSeconds()).toBe(0);
    expect(exp!.getMilliseconds()).toBe(0);
  });

  it('should normalize expiration from string', () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.withExpiration('2025-06-15T14:22:33Z');

    const exp = builder.expiresAt;
    expect(exp!.getSeconds()).toBe(0);
  });

  it('should generate a valid JWS RS256 signature', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('signed-data'), 'doc.pdf');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    const sig = built.capsa.signature;
    expect(sig.algorithm).toBe('RS256');
    expect(sig.protected).toBeTruthy();
    expect(sig.payload).toBeTruthy();
    expect(sig.signature).toBeTruthy();

    // Signature should be base64url encoded 512-byte RSA-4096 signature
    const sigBuffer = Buffer.from(sig.signature, 'base64url');
    expect(sigBuffer.length).toBe(512);
  });

  it('should apply compression only for files above 150 byte threshold', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';

    // Small file (below threshold)
    builder.addFileFromBuffer(Buffer.from('tiny'), 'small.txt');
    // Larger file (above threshold) - use repetitive data that compresses well
    builder.addFileFromBuffer(Buffer.from('a'.repeat(500)), 'big.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    const smallFile = built.capsa.files[0]!;
    const bigFile = built.capsa.files[1]!;

    // Small file should not be compressed
    expect(smallFile.compressed).toBeUndefined();
    // Large file should be compressed
    expect(bigFile.compressed).toBe(true);
    expect(bigFile.compressionAlgorithm).toBe('gzip');
    expect(bigFile.originalSize).toBe(500);
  });

  it('should generate packageId with capsa_ prefix', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    expect(built.capsa.packageId).toMatch(/^capsa_/);
  });

  it('should generate fileId with file_ prefix and .enc extension', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    expect(built.capsa.files[0]!.fileId).toMatch(/^file_.*\.enc$/);
  });

  it('should encrypt subject, body, and structured data', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.withSubject('Test Subject');
    builder.withBody('Test Body');
    builder.withStructured('claimId', 'CLM-123');
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    expect(built.capsa.encryptedSubject).toBeTruthy();
    expect(built.capsa.subjectIV).toBeTruthy();
    expect(built.capsa.subjectAuthTag).toBeTruthy();
    expect(built.capsa.encryptedBody).toBeTruthy();
    expect(built.capsa.bodyIV).toBeTruthy();
    expect(built.capsa.bodyAuthTag).toBeTruthy();
    expect(built.capsa.encryptedStructured).toBeTruthy();
    expect(built.capsa.structuredIV).toBeTruthy();
    expect(built.capsa.structuredAuthTag).toBeTruthy();
  });

  it('should not include encrypted fields when not set', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    expect(built.capsa.encryptedSubject).toBeUndefined();
    expect(built.capsa.encryptedBody).toBeUndefined();
    expect(built.capsa.encryptedStructured).toBeUndefined();
  });

  it('should create keychain entries for creator and recipients', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addRecipient('recipient_1');
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    const partyKeys = [
      makePartyKey('creator_1', creatorKeys),
      makePartyKey('recipient_1', recipientKeys),
    ];
    const built = await builder.build(partyKeys);

    const keys = built.capsa.keychain.keys;
    expect(keys.length).toBe(2);

    const creatorEntry = keys.find(k => k.party === 'creator_1');
    const recipientEntry = keys.find(k => k.party === 'recipient_1');

    expect(creatorEntry).toBeDefined();
    expect(recipientEntry).toBeDefined();
    // Both should have encrypted keys
    expect(creatorEntry!.encryptedKey).toBeTruthy();
    expect(recipientEntry!.encryptedKey).toBeTruthy();
  });

  it('should handle delegation: delegate with key and actingFor exactly the principal', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addRecipient('recipient_1');
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    // Delegate acts for recipient_1 and for a party not on this capsa
    const partyKeys = [
      makePartyKey('creator_1', creatorKeys),
      { ...makePartyKey('recipient_1', recipientKeys) },
      makePartyKey('delegate_1', delegateKeys, ['other_principal', 'recipient_1']),
    ];
    const built = await builder.build(partyKeys);

    const keys = built.capsa.keychain.keys;
    const delegateEntry = keys.find(k => k.party === 'delegate_1');

    expect(delegateEntry).toBeDefined();
    expect(delegateEntry!.encryptedKey).toBeTruthy();
    expect(delegateEntry!.permissions).toEqual(['delegate']);
    expect(delegateEntry!.actingFor).toEqual(['recipient_1']);
  });

  it('should reject a second recipient', () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');

    expect(() => builder.addRecipient('recipient_2')).toThrow(/already has a recipient/);
  });

  it('should reject build with no recipient', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    // Deliberately no addRecipient()
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    await expect(builder.build([makePartyKey('creator_1', creatorKeys)])).rejects.toThrow(
      /no recipient/
    );
  });

  it('should support fluent API chaining', () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    const result = builder
      .addRecipient('r1')
      .withSubject('subj')
      .withBody('body')
      .withStructured('key', 'value')
      .withExpiration(new Date());

    expect(result).toBe(builder);
  });

  it('should set file-level expiration with seconds zeroed', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFile({
      buffer: Buffer.from('data'),
      filename: 'f.txt',
      expiresAt: new Date('2027-06-01T10:30:45Z'),
    });

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    const fileExp = built.capsa.files[0]!.expiresAt;
    expect(fileExp).toBeDefined();
    // Seconds should be zeroed
    expect(fileExp).toMatch(/:00\.000Z$/);
  });

  it('should reject a file expiring after the capsa', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-06-30T12:00:00Z';
    builder.addFile({
      buffer: Buffer.from('data'),
      filename: 'outlives.txt',
      expiresAt: new Date('2027-07-01T12:00:00Z'),
    });

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    await expect(builder.build(partyKeys)).rejects.toThrow(
      /outlives\.txt.*after the capsa expires/s
    );
  });

  it('should accept a file expiring with the capsa', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-06-30T12:00:00Z';
    builder.addFile({
      buffer: Buffer.from('data'),
      filename: 'same.txt',
      expiresAt: new Date('2027-06-30T12:00:00Z'),
    });

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    expect(built.capsa.files[0]!.expiresAt).toBe('2027-06-30T12:00:00.000Z');
  });

  it('should require file input to have path or buffer', () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);

    expect(() => builder.addFile({ filename: 'no-data.txt' })).toThrow(
      /path or buffer/
    );
  });

  it('should set SHA-256 hash algorithm on files', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('test'), 'test.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    expect(built.capsa.files[0]!.hashAlgorithm).toBe('SHA-256');
  });

  it('should produce hex SHA-256 hash for each file', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addRecipient('recipient_1');
    builder.expiresAt = '2027-12-31T23:59:00Z';
    builder.addFileFromBuffer(Buffer.from('hashme'), 'test.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
    const built = await builder.build(partyKeys);

    const hash = built.capsa.files[0]!.hash;
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  // ==========================================================================
  // Defense-in-Depth: Server-Aligned Pre-Flight Validations
  // ==========================================================================

  describe('keychain size limit (server: max 100 keychain entries)', () => {
    it('should reject a keychain over the limit (creator + recipient + 99 delegates)', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addRecipient('recipient_1');
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

      const delegates = Array.from({ length: 99 }, (_, i) =>
        makePartyKey(`delegate_${i}`, delegateKeys, ['recipient_1'])
      );
      const partyKeys = [
        makePartyKey('creator_1', creatorKeys),
        makePartyKey('recipient_1', recipientKeys),
        ...delegates,
      ];

      await expect(builder.build(partyKeys)).rejects.toThrow(/exceeding the server limit of 100/);
    });
  });

  describe('encrypted field size limits (server-aligned)', () => {
    it('should reject encrypted subject exceeding 64KB', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

      // 64KB of text + base64url overhead will exceed server's 65536 char limit
      builder.withSubject('x'.repeat(60_000));

      const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/subject.*exceeds server limit/i);
    });

    it('should accept subject within 64KB limit', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

      // Small subject well within limit
      builder.withSubject('Normal subject line');

      const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
      const built = await builder.build(partyKeys);
      expect(built.capsa.encryptedSubject).toBeTruthy();
    });

    it('should reject encrypted body exceeding 1MB', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

      // 1MB of text + base64url overhead will exceed server's 1MB limit
      builder.withBody('x'.repeat(900_000));

      const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/body.*exceeds server limit/i);
    });

    it('should reject encrypted structured data exceeding 1MB', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

      // Build a large structured object
      const bigValue = 'x'.repeat(900_000);
      builder.withStructured('bigField', bigValue);

      const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/structured.*exceeds server limit/i);
    });
  });

  describe('metadata field size limits (server-aligned)', () => {
    it('should reject metadata label exceeding 512 chars', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');
      builder.metadata.label = 'x'.repeat(513);

      const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/label.*512/);
    });

    it('should reject more than 100 tags', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');
      builder.metadata.tags = Array.from({ length: 101 }, (_, i) => `tag_${i}`);

      const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/tags count.*100/);
    });

    it('should reject individual tag exceeding 100 chars', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');
      builder.metadata.tags = ['x'.repeat(101)];

      const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/tag.*100 chars/);
    });

    it('should reject metadata notes exceeding 10KB', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');
      builder.metadata.notes = 'x'.repeat(10_241);

      const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/notes.*10240/);
    });

    it('should reject more than 50 related packages', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');
      builder.metadata.relatedPackages = Array.from({ length: 51 }, (_, i) => `pkg_${i}`);

      const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/related packages.*50/i);
    });
  });

  describe('duplicate IV detection (defense-in-depth)', () => {
    it('should produce globally unique IVs across all fields in a build', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.withSubject('test');
      builder.withBody('test body');
      builder.withStructured('key', 'val');
      builder.addRecipient('recipient_1');
      builder.addFileFromBuffer(Buffer.from('file1'), 'a.txt');
      builder.addFileFromBuffer(Buffer.from('file2'), 'b.txt');

      const partyKeys = [
        makePartyKey('creator_1', creatorKeys),
        makePartyKey('recipient_1', recipientKeys),
      ];
      const built = await builder.build(partyKeys);

      // Collect ALL IVs from the built capsa
      const allIVs: string[] = [];
      if (built.capsa.subjectIV) allIVs.push(built.capsa.subjectIV);
      if (built.capsa.bodyIV) allIVs.push(built.capsa.bodyIV);
      if (built.capsa.structuredIV) allIVs.push(built.capsa.structuredIV);
      for (const key of built.capsa.keychain.keys) {
        if (key.iv) allIVs.push(key.iv);
      }
      for (const file of built.capsa.files) {
        allIVs.push(file.iv);
        allIVs.push(file.filenameIV);
      }

      // All IVs must be globally unique
      const unique = new Set(allIVs);
      expect(unique.size).toBe(allIVs.length);
      // 2 files * 2 IVs (content + filename) + 3 metadata (subject, body, structured) + 2 keychain = 9 IVs
      expect(allIVs.length).toBeGreaterThanOrEqual(9);
    });
  });

  describe('party ID validation', () => {
    it('should reject empty party ID', () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      expect(() => builder.addRecipient('')).toThrow(/empty/i);
    });

    it('should reject party ID exceeding 100 chars', () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      const longId = 'x'.repeat(101);
      expect(() => builder.addRecipient(longId)).toThrow(/100/);
    });
  });

  describe('no-content guard', () => {
    it('should reject build with no files and no subject/body', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addRecipient('recipient_1');
      // structured data alone doesn't count as content
      builder.withStructured('key', 'val');

      const partyKeys = [
        makePartyKey('creator_1', creatorKeys),
        makePartyKey('recipient_1', recipientKeys),
      ];
      await expect(builder.build(partyKeys)).rejects.toThrow(/files.*message|empty/i);
    });

    it('should allow build with only subject (no files)', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.expiresAt = '2027-12-31T23:59:00Z';
      builder.addRecipient('recipient_1');
      builder.withSubject('Just a message');

      const partyKeys = [
        makePartyKey('creator_1', creatorKeys),
        makePartyKey('recipient_1', recipientKeys),
      ];
      const built = await builder.build(partyKeys);
      expect(built.capsa.encryptedSubject).toBeDefined();
      expect(built.files).toHaveLength(0);
    });
  });

  describe('encrypted filename length limit', () => {
    it('should reject filename that produces encrypted output exceeding 2048 chars', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      // 1540 + 4 (.txt) = 1544 bytes → AES-GCM → 1544 bytes → base64url → 2059 chars > 2048
      const longFilename = 'a'.repeat(1540) + '.txt';
      builder.addFileFromBuffer(Buffer.from('data'), longFilename);

      const partyKeys = [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/encrypted filename.*2048|2,048/i);
    });
  });

  describe('signature payload limit', () => {
    it('should have MAX_SIGNATURE_PAYLOAD constant of 65536', () => {
      expect(SERVER_LIMITS.MAX_SIGNATURE_PAYLOAD).toBe(65_536);
    });
  });

  describe('SERVER_LIMITS constants match server Zod schema', () => {
    it('should have correct limit values', () => {
      expect(SERVER_LIMITS.MAX_KEYCHAIN_KEYS).toBe(100);
      expect(SERVER_LIMITS.MAX_ENCRYPTED_SUBJECT).toBe(65_536);
      expect(SERVER_LIMITS.MAX_ENCRYPTED_BODY).toBe(1_048_576);
      expect(SERVER_LIMITS.MAX_ENCRYPTED_STRUCTURED).toBe(1_048_576);
      expect(SERVER_LIMITS.MAX_METADATA_LABEL).toBe(512);
      expect(SERVER_LIMITS.MAX_METADATA_TAGS).toBe(100);
      expect(SERVER_LIMITS.MAX_TAG_LENGTH).toBe(100);
      expect(SERVER_LIMITS.MAX_METADATA_NOTES).toBe(10_240);
      expect(SERVER_LIMITS.MAX_RELATED_PACKAGES).toBe(50);
      expect(SERVER_LIMITS.MAX_PARTY_ID_LENGTH).toBe(100);
      expect(SERVER_LIMITS.MAX_ENCRYPTED_FILENAME).toBe(2_048);
      expect(SERVER_LIMITS.MAX_SIGNATURE_PAYLOAD).toBe(65_536);
      expect(SERVER_LIMITS).not.toHaveProperty('MAX_ACTING_FOR');
    });
  });

  it('should sign the creator id and its key fingerprint right after the algorithm', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS)
      .addRecipient('recipient_1')
      .withSubject('signed')
      .withExpiration('2027-12-31T23:59:00Z');

    const built = await builder.build([makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)]);
    const parts = Buffer.from(built.capsa.signature.payload, 'base64url').toString('utf-8').split('|');

    expect(parts.slice(0, 6)).toEqual([
      built.capsa.packageId,
      '1.0.0',
      '0',
      'AES-256-GCM',
      'creator_1',
      createFingerprint(creatorKeys.publicKey),
    ]);
    expect(parts[6]).toBe(`subject:${built.capsa.subjectIV}`);
  });

  it('should sign the subject and body IVs with their labels', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS)
      .addRecipient('recipient_1')
      .withSubject('s')
      .withBody('b')
      .withExpiration('2027-12-31T23:59:00Z');

    const built = await builder.build([makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)]);
    const parts = Buffer.from(built.capsa.signature.payload, 'base64url').toString('utf-8').split('|');

    expect(parts.slice(6)).toEqual([`subject:${built.capsa.subjectIV}`, `body:${built.capsa.bodyIV}`]);
  });

  describe('recipient keys and client-side request limits', () => {
    function newBuilder(): CapsaBuilder {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('recipient_1');
      builder.expiresAt = '2027-12-31T23:59:00Z';
      return builder;
    }

    const bothKeys = (): PartyKey[] => [makePartyKey('creator_1', creatorKeys), makePartyKey('recipient_1', recipientKeys)];

    it('fails with RECIPIENT_KEY_NOT_FOUND when the recipient has no party key', async () => {
      const builder = newBuilder().withSubject('hi');

      await expect(builder.build([makePartyKey('creator_1', creatorKeys)])).rejects.toMatchObject({
        name: 'CapsaraError',
        code: 'RECIPIENT_KEY_NOT_FOUND',
        details: { partyId: 'recipient_1' },
        message: 'Recipient recipient_1 has no registered public key',
      });
    });

    it('fails with RECIPIENT_KEY_NOT_FOUND when the recipient key is empty', async () => {
      const builder = newBuilder().withSubject('hi');
      const keys = [makePartyKey('creator_1', creatorKeys), { ...makePartyKey('recipient_1', recipientKeys), publicKey: '' }];

      await expect(builder.build(keys)).rejects.toMatchObject({ code: 'RECIPIENT_KEY_NOT_FOUND' });
    });

    it('accepts a self-send when the creator is the recipient and has a key', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS)
        .addRecipient('creator_1')
        .withSubject('note to self')
        .withExpiration('2027-12-31T23:59:00Z');

      const built = await builder.build([makePartyKey('creator_1', creatorKeys)]);

      expect(built.capsa.keychain.keys.map(k => k.party)).toContain('creator_1');
    });

    it('rejects an empty file buffer', async () => {
      const builder = newBuilder().addFileFromBuffer(Buffer.alloc(0), 'empty.txt');

      await expect(builder.build(bothKeys())).rejects.toThrow('File "empty.txt" is empty');
    });

    it('rejects an empty file on disk', async () => {
      const fs = await import('fs');
      const os = await import('os');
      const path = await import('path');
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'capsa-empty-'));
      const file = path.join(dir, 'zero.bin');
      fs.writeFileSync(file, Buffer.alloc(0));
      try {
        const builder = newBuilder().addFileFromPath(file);
        await expect(builder.build(bothKeys())).rejects.toThrow('File "zero.bin" is empty');
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it('accepts a one-byte file', async () => {
      const builder = newBuilder().addFileFromBuffer(Buffer.from('x'), 'one.txt');

      await expect(builder.build(bothKeys())).resolves.toBeDefined();
    });

    it('rejects a capsa whose JSON part exceeds 1 MiB even when each field is within its own limit', async () => {
      const builder = newBuilder()
        .withBody('b'.repeat(600_000))
        .withStructured({ blob: 's'.repeat(600_000) });

      await expect(builder.build(bothKeys())).rejects.toThrow(/exceeds the server limit of 1048576 bytes per JSON field/);
    });

    it('accepts a capsa whose JSON part is under 1 MiB', async () => {
      const builder = newBuilder().withBody('b'.repeat(500_000));

      const built = await builder.build(bothKeys());

      expect(Buffer.byteLength(JSON.stringify(built.capsa))).toBeLessThanOrEqual(SERVER_LIMITS.MAX_JSON_FIELD);
    });
  });
});
