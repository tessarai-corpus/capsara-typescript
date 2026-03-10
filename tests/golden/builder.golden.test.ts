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

function generateTestKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

const DEFAULT_LIMITS: SystemLimits = {
  maxFileSize: 100 * 1024 * 1024,      // 100MB
  maxFilesPerCapsa: 500,
  maxTotalSize: 500 * 1024 * 1024,     // 500MB
};

let creatorKeys: { publicKey: string; privateKey: string };
let recipientKeys: { publicKey: string; privateKey: string };
let delegateKeys: { publicKey: string; privateKey: string };

beforeAll(() => {
  creatorKeys = generateTestKeyPair();
  recipientKeys = generateTestKeyPair();
  delegateKeys = generateTestKeyPair();
});

function createFingerprint(publicKey: string): string {
  return crypto.createHash('sha256').update(publicKey).digest('hex');
}

function makePartyKey(id: string, keys: { publicKey: string }, isDelegate?: string[]): PartyKey {
  return {
    id,
    email: `${id}@test.com`,
    publicKey: keys.publicKey,
    fingerprint: createFingerprint(keys.publicKey),
    isDelegate,
  };
}

describe('Golden: Builder', () => {
  it('should generate a 32-byte master key on construction', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addFileFromBuffer(Buffer.from('test'), 'test.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
    const built = await builder.build(partyKeys);

    // The keychain should have an entry for creator
    expect(built.capsa.keychain.keys.length).toBeGreaterThanOrEqual(1);
    // Algorithm should be AES-256-GCM
    expect(built.capsa.keychain.algorithm).toBe('AES-256-GCM');
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

    // Each file will be slightly larger after encryption; use enough data to exceed 50 bytes total
    builder.addFileFromBuffer(Buffer.from('x'.repeat(30)), 'a.txt');
    builder.addFileFromBuffer(Buffer.from('x'.repeat(30)), 'b.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
    await expect(builder.build(partyKeys)).rejects.toThrow(/exceeds maximum/);
  });

  it('should produce unique IVs for each file within a single build', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addFileFromBuffer(Buffer.from('file1'), 'a.txt');
    builder.addFileFromBuffer(Buffer.from('file2'), 'b.txt');
    builder.addFileFromBuffer(Buffer.from('file3'), 'c.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
    const built = await builder.build(partyKeys);

    const ivs = built.capsa.files.map(f => f.iv);
    const uniqueIVs = new Set(ivs);
    expect(uniqueIVs.size).toBe(ivs.length);
  });

  it('should produce unique filename IVs for each file', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addFileFromBuffer(Buffer.from('f1'), 'a.txt');
    builder.addFileFromBuffer(Buffer.from('f2'), 'b.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
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
    builder.addFileFromBuffer(Buffer.from('signed-data'), 'doc.pdf');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
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

    // Small file (below threshold)
    builder.addFileFromBuffer(Buffer.from('tiny'), 'small.txt');
    // Larger file (above threshold) - use repetitive data that compresses well
    builder.addFileFromBuffer(Buffer.from('a'.repeat(500)), 'big.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
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
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
    const built = await builder.build(partyKeys);

    expect(built.capsa.packageId).toMatch(/^capsa_/);
  });

  it('should generate fileId with file_ prefix and .enc extension', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
    const built = await builder.build(partyKeys);

    expect(built.capsa.files[0]!.fileId).toMatch(/^file_.*\.enc$/);
  });

  it('should encrypt subject, body, and structured data', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.withSubject('Test Subject');
    builder.withBody('Test Body');
    builder.withStructured('claimId', 'CLM-123');
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
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
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
    const built = await builder.build(partyKeys);

    expect(built.capsa.encryptedSubject).toBeUndefined();
    expect(built.capsa.encryptedBody).toBeUndefined();
    expect(built.capsa.encryptedStructured).toBeUndefined();
  });

  it('should create keychain entries for creator and recipients', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
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

  it('should handle delegation: delegated recipient with no key, delegate with key and actingFor', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    // Recipient_1 is a delegated recipient (no key, permissions empty)
    builder.addRecipients('recipient_1');
    builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

    // Delegate acts for recipient_1
    const partyKeys = [
      makePartyKey('creator_1', creatorKeys),
      { ...makePartyKey('recipient_1', recipientKeys) },
      makePartyKey('delegate_1', delegateKeys, ['recipient_1']),
    ];
    const built = await builder.build(partyKeys);

    const keys = built.capsa.keychain.keys;
    const delegateEntry = keys.find(k => k.party === 'delegate_1');

    expect(delegateEntry).toBeDefined();
    expect(delegateEntry!.encryptedKey).toBeTruthy();
    expect(delegateEntry!.permissions).toContain('delegate');
    expect(delegateEntry!.actingFor).toContain('recipient_1');
  });

  it('should support fluent API chaining', () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    const result = builder
      .addRecipient('r1')
      .addRecipients('r2', 'r3')
      .withSubject('subj')
      .withBody('body')
      .withStructured('key', 'value')
      .withExpiration(new Date());

    expect(result).toBe(builder);
  });

  it('should set file-level expiration with seconds zeroed', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addFile({
      buffer: Buffer.from('data'),
      filename: 'f.txt',
      expiresAt: new Date('2025-12-01T10:30:45Z'),
    });

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
    const built = await builder.build(partyKeys);

    const fileExp = built.capsa.files[0]!.expiresAt;
    expect(fileExp).toBeDefined();
    // Seconds should be zeroed
    expect(fileExp).toMatch(/:00\.000Z$/);
  });

  it('should require file input to have path or buffer', () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);

    expect(() => builder.addFile({ filename: 'no-data.txt' })).toThrow(
      /path or buffer/
    );
  });

  it('should set SHA-256 hash algorithm on files', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addFileFromBuffer(Buffer.from('test'), 'test.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
    const built = await builder.build(partyKeys);

    expect(built.capsa.files[0]!.hashAlgorithm).toBe('SHA-256');
  });

  it('should produce hex SHA-256 hash for each file', async () => {
    const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
    builder.addFileFromBuffer(Buffer.from('hashme'), 'test.txt');

    const partyKeys = [makePartyKey('creator_1', creatorKeys)];
    const built = await builder.build(partyKeys);

    const hash = built.capsa.files[0]!.hash;
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  // ==========================================================================
  // Defense-in-Depth: Server-Aligned Pre-Flight Validations
  // ==========================================================================

  describe('recipient count limits (server: max 100 keychain entries)', () => {
    it('should reject when adding too many recipients exceeds keychain limit', () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);

      // Add 99 recipients (+ 1 creator = 100 total = at the limit, still valid)
      for (let i = 0; i < 99; i++) {
        builder.addRecipient(`party_${i}`);
      }

      // The 100th recipient would make 101 total (100 recipients + 1 creator) = over limit
      expect(() => builder.addRecipient('one_too_many')).toThrow(/exceed.*100/i);
    });

    it('should reject addRecipients batch that would exceed keychain limit', () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addRecipient('existing_1');

      const tooMany = Array.from({ length: 100 }, (_, i) => `batch_${i}`);
      expect(() => builder.addRecipients(...tooMany)).toThrow(/100/);
    });
  });

  describe('encrypted field size limits (server-aligned)', () => {
    it('should reject encrypted subject exceeding 64KB', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

      // 64KB of text + base64url overhead will exceed server's 65536 char limit
      builder.withSubject('x'.repeat(60_000));

      const partyKeys = [makePartyKey('creator_1', creatorKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/subject.*exceeds server limit/i);
    });

    it('should accept subject within 64KB limit', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

      // Small subject well within limit
      builder.withSubject('Normal subject line');

      const partyKeys = [makePartyKey('creator_1', creatorKeys)];
      const built = await builder.build(partyKeys);
      expect(built.capsa.encryptedSubject).toBeTruthy();
    });

    it('should reject encrypted body exceeding 1MB', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

      // 1MB of text + base64url overhead will exceed server's 1MB limit
      builder.withBody('x'.repeat(900_000));

      const partyKeys = [makePartyKey('creator_1', creatorKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/body.*exceeds server limit/i);
    });

    it('should reject encrypted structured data exceeding 1MB', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');

      // Build a large structured object
      const bigValue = 'x'.repeat(900_000);
      builder.withStructured('bigField', bigValue);

      const partyKeys = [makePartyKey('creator_1', creatorKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/structured.*exceeds server limit/i);
    });
  });

  describe('metadata field size limits (server-aligned)', () => {
    it('should reject metadata label exceeding 512 chars', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');
      builder.metadata.label = 'x'.repeat(513);

      const partyKeys = [makePartyKey('creator_1', creatorKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/label.*512/);
    });

    it('should reject more than 100 tags', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');
      builder.metadata.tags = Array.from({ length: 101 }, (_, i) => `tag_${i}`);

      const partyKeys = [makePartyKey('creator_1', creatorKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/tags count.*100/);
    });

    it('should reject individual tag exceeding 100 chars', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');
      builder.metadata.tags = ['x'.repeat(101)];

      const partyKeys = [makePartyKey('creator_1', creatorKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/tag.*100 chars/);
    });

    it('should reject metadata notes exceeding 10KB', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');
      builder.metadata.notes = 'x'.repeat(10_241);

      const partyKeys = [makePartyKey('creator_1', creatorKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/notes.*10240/);
    });

    it('should reject more than 50 related packages', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      builder.addFileFromBuffer(Buffer.from('data'), 'f.txt');
      builder.metadata.relatedPackages = Array.from({ length: 51 }, (_, i) => `pkg_${i}`);

      const partyKeys = [makePartyKey('creator_1', creatorKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/related packages.*50/i);
    });
  });

  describe('duplicate IV detection (defense-in-depth)', () => {
    it('should produce globally unique IVs across all fields in a build', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
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

    it('should reject empty party ID in addRecipients batch', () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
      expect(() => builder.addRecipients('valid_id', '')).toThrow(/empty/i);
    });
  });

  describe('no-content guard', () => {
    it('should reject build with no files and no subject/body', async () => {
      const builder = new CapsaBuilder('creator_1', creatorKeys.privateKey, DEFAULT_LIMITS);
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
      // 1540 + 4 (.txt) = 1544 bytes → AES-GCM → 1544 bytes → base64url → 2059 chars > 2048
      const longFilename = 'a'.repeat(1540) + '.txt';
      builder.addFileFromBuffer(Buffer.from('data'), longFilename);

      const partyKeys = [makePartyKey('creator_1', creatorKeys)];
      await expect(builder.build(partyKeys)).rejects.toThrow(/encrypted filename.*2048|2,048/i);
    });
  });

  describe('signature payload limit', () => {
    it('should have MAX_SIGNATURE_PAYLOAD constant of 65536', () => {
      expect(SERVER_LIMITS.MAX_SIGNATURE_PAYLOAD).toBe(65_536);
    });
  });

  describe('actingFor delegate limit', () => {
    it('should have MAX_ACTING_FOR constant of 10', () => {
      expect(SERVER_LIMITS.MAX_ACTING_FOR).toBe(10);
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
      expect(SERVER_LIMITS.MAX_ACTING_FOR).toBe(10);
    });
  });
});
