/** Fluent capsa builder for creating encrypted capsas. */

import * as fs from 'fs';
import * as path from 'path';
import { generateId } from '../internal/utils/id-generator.js';
import { lookupMimeType } from '../internal/utils/mimetype-lookup.js';
import { filenameSendProblem } from '../internal/utils/filename-check.js';
import { CapsaraError } from '../errors/capsara-error.js';
import {
  generateMasterKey,
  generateIV,
  encryptAES,
  encryptAESRaw,
  encryptMasterKeyForParty,
  computeHash,
} from '../internal/crypto/primitives.js';
import {
  buildCanonicalString,
  createCapsaSignature,
} from '../internal/crypto/signatures.js';
import { calculatePrivateKeyFingerprint } from '../internal/crypto/key-generator.js';
import {
  compressData,
  shouldCompress,
} from '../internal/crypto/compression.js';
import type {
  FileInput,
  RecipientConfig,
  PartyKey,
  Capsa,
  SystemLimits,
} from '../types/index.js';
import type {
  CapsaMetadata,
  KeychainEntry,
  EncryptedFile,
  FileEncryptionResult,
} from '../internal/types.js';

/** Capsa metadata for upload */
export interface CapsaUploadData {
  packageId: string;
  keychain: { algorithm: string; keys: KeychainEntry[] };
  signature: { algorithm: string; protected: string; payload: string; signature: string };
  accessControl: { expiresAt?: string };
  deliveryPriority: string;
  files: EncryptedFile[];
  metadata?: CapsaMetadata;
  encryptedSubject?: string;
  subjectIV?: string;
  subjectAuthTag?: string;
  encryptedBody?: string;
  bodyIV?: string;
  bodyAuthTag?: string;
  encryptedStructured?: string;
  structuredIV?: string;
  structuredAuthTag?: string;
}

/** Built capsa ready for upload */
export interface BuiltCapsa {
  capsa: CapsaUploadData;
  files: Array<{ metadata: EncryptedFile; data: Buffer }>;
}

/** Server-aligned validation constants. */
export const SERVER_LIMITS = {
  /** Maximum keychain entries (creator + recipient + delegates) */
  MAX_KEYCHAIN_KEYS: 100,
  /** Maximum base64url-encoded encrypted subject length */
  MAX_ENCRYPTED_SUBJECT: 65_536,
  /** Maximum base64url-encoded encrypted body length */
  MAX_ENCRYPTED_BODY: 1_048_576,
  /** Maximum base64url-encoded encrypted structured data length */
  MAX_ENCRYPTED_STRUCTURED: 1_048_576,
  /** Maximum metadata label length */
  MAX_METADATA_LABEL: 512,
  /** Maximum tags per envelope */
  MAX_METADATA_TAGS: 100,
  /** Maximum characters per tag */
  MAX_TAG_LENGTH: 100,
  /** Maximum metadata notes length */
  MAX_METADATA_NOTES: 10_240,
  /** Maximum related packages */
  MAX_RELATED_PACKAGES: 50,
  /** Maximum party ID length */
  MAX_PARTY_ID_LENGTH: 100,
  /** Maximum base64url-encoded encrypted filename length */
  MAX_ENCRYPTED_FILENAME: 2_048,
  /** Maximum base64url-encoded signature payload length */
  MAX_SIGNATURE_PAYLOAD: 65_536,
  /** Maximum UTF-8 bytes of one JSON part in the upload request (the serialized capsa) */
  MAX_JSON_FIELD: 1_048_576,
} as const;

/** Error message when a capsa is built without a recipient. */
const NO_RECIPIENT_MESSAGE =
  'Capsa has no recipient. Call addRecipient() with the party this capsa is sent to.';

function validationError(message: string): CapsaraError {
  return new CapsaraError(message, 'VALIDATION_ERROR', 0);
}

const DAY_MS = 24 * 60 * 60 * 1000;

const FALLBACK_MAX_EXPIRATION_DAYS = 3650;

function maxExpirationDays(limits: SystemLimits): number {
  const value = limits.maxExpirationDays;
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : FALLBACK_MAX_EXPIRATION_DAYS;
}

function buildFailed(reason: string, message: string): CapsaraError {
  return new CapsaraError(message, 'BUILD_FAILED', 0, { reason });
}

function readFileAt(filePath: string): Buffer {
  try {
    return fs.readFileSync(filePath);
  } catch (error) {
    throw buildFailed('FILE_READ_FAILED', `Cannot read file "${filePath}": ${error instanceof Error ? error.message : String(error)}`);
  }
}

function fileSizeAt(filePath: string): number {
  try {
    return fs.statSync(filePath).size;
  } catch (error) {
    throw validationError(`Cannot read file "${filePath}": ${error instanceof Error ? error.message : String(error)}`);
  }
}

export class CapsaBuilder {
  subject?: string;
  body?: string;
  structured: Record<string, unknown> = {};

  /** Unencrypted metadata */
  readonly metadata: CapsaMetadata = {};

  /** Expiration date (UTC, rounded to minute) */
  get expiresAt(): Date | undefined {
    return this.#expiresAt ? new Date(this.#expiresAt) : undefined;
  }
  set expiresAt(value: Date | string | undefined) {
    if (value === undefined) {
      this.#expiresAt = undefined;
      return;
    }
    const dateObj = typeof value === 'string' ? new Date(value) : new Date(value.getTime());
    if (Number.isNaN(dateObj.getTime())) {
      throw validationError(`Invalid expiration date: ${String(value)}`);
    }
    dateObj.setSeconds(0, 0);
    this.#expiresAt = dateObj.toISOString();
  }

  #masterKey: Buffer;
  #creatorId: string;
  #recipients: RecipientConfig[] = [];
  #files: Array<{ input: FileInput; encrypted?: FileEncryptionResult }> = [];
  #creatorPrivateKey: string;
  #limits: SystemLimits;
  #expiresAt?: string;

  constructor(creatorId: string, creatorPrivateKey: string, limits: SystemLimits) {
    this.#masterKey = generateMasterKey();
    this.#creatorId = creatorId;
    this.#creatorPrivateKey = creatorPrivateKey;
    this.#limits = limits;
  }

  /**
   * Set the capsa's recipient (its principal).
   *
   * A capsa goes to exactly one recipient. The recipient's registered delegates
   * are added automatically at send time, each acting for this recipient, so
   * several parties can still access the capsa through their own keys. To send
   * to several recipients, use one builder per recipient and send them together
   * in one batch with sendCapsas().
   *
   * The recipient may be the creator itself (a self-send); the creator's own
   * delegates are then added, acting for the creator.
   * @param partyId - Party ID
   * @throws Error if a recipient has already been added
   */
  addRecipient(partyId: string): this {
    if (!partyId || partyId.length === 0) {
      throw validationError('Party ID cannot be empty.');
    }
    if (partyId.length > SERVER_LIMITS.MAX_PARTY_ID_LENGTH) {
      throw validationError(
        `Party ID (${partyId.length} chars) exceeds server limit of ${SERVER_LIMITS.MAX_PARTY_ID_LENGTH} chars.`
      );
    }
    const existing = this.#recipients[0];
    if (existing) {
      throw validationError(
        `Capsa already has a recipient ("${existing.partyId}"). A capsa goes to exactly one recipient; ` +
        `that recipient's delegates are added automatically. To send to several recipients, ` +
        `create one builder per recipient and send them together in one batch.`
      );
    }
    this.#recipients.push({ partyId, permissions: ['read'] });
    return this;
  }

  /**
   * Add a file to the capsa
   * @param input - File input (path or buffer with filename)
   * @throws CapsaraError (VALIDATION_ERROR) if the file name contains "/", "\" or
   * control characters, is empty or only spaces, or is "." or ".."; if the file
   * exceeds the size limit; or if the capsa already has the maximum number of files
   */
  addFile(input: FileInput): this {
    const filenameProblem = filenameSendProblem(input.filename);
    if (filenameProblem) {
      throw validationError(filenameProblem);
    }

    if (this.#files.length >= this.#limits.maxFilesPerCapsa) {
      throw validationError(
        `Cannot add file: capsa already has ${this.#files.length} files (max: ${this.#limits.maxFilesPerCapsa})`
      );
    }

    let fileSize: number;
    if (input.buffer) {
      fileSize = input.buffer.length;
    } else if (input.path) {
      fileSize = fileSizeAt(input.path);
    } else {
      throw validationError('File input must have either path or buffer');
    }

    if (fileSize > this.#limits.maxFileSize) {
      throw validationError(
        `File "${input.filename}" exceeds maximum size of ${Math.floor(this.#limits.maxFileSize / 1024 / 1024)}MB (${fileSize} bytes)`
      );
    }

    this.#files.push({ input });
    return this;
  }

  /**
   * Add a file from a file path
   * @param filePath - File path on disk
   * @param filename - Filename override (defaults to basename)
   * @param mimetype - MIME type (auto-detected if not specified)
   */
  addFileFromPath(filePath: string, filename?: string, mimetype?: string): this {
    const resolvedFilename = filename ?? path.basename(filePath);
    return this.addFile({ path: filePath, filename: resolvedFilename, mimetype });
  }

  /**
   * Add a file from a Buffer
   * @param buffer - File content
   * @param filename - Filename
   * @param mimetype - MIME type (auto-detected if not specified)
   */
  addFileFromBuffer(buffer: Buffer, filename: string, mimetype?: string): this {
    return this.addFile({ buffer, filename, mimetype });
  }

  /**
   * Add multiple files from file paths
   * @param paths - File paths on disk
   */
  addFiles(...paths: string[]): this {
    for (const path of paths) {
      this.addFileFromPath(path);
    }
    return this;
  }

  /**
   * Add multiple files from FileInput objects
   * @param files - File inputs
   */
  addFilesFromInputs(...files: FileInput[]): this {
    for (const file of files) {
      this.addFile(file);
    }
    return this;
  }

  /**
   * Add a text file from string content
   * @param filename - Filename
   * @param content - Text content
   */
  addTextFile(filename: string, content: string): this {
    const buffer = Buffer.from(content, 'utf-8');
    return this.addFile({ buffer, filename, mimetype: 'text/plain' });
  }

  /**
   * Add a JSON file from an object
   * @param filename - Filename
   * @param data - Object to serialize as JSON
   */
  addJsonFile(filename: string, data: unknown): this {
    const json = JSON.stringify(data);
    const buffer = Buffer.from(json, 'utf-8');
    return this.addFile({ buffer, filename, mimetype: 'application/json' });
  }

  /**
   * Set a structured data field
   * @param key - Field key
   * @param value - Field value
   */
  withStructured(key: string, value: unknown): this;
  /**
   * Set multiple structured data fields from an object
   * @param data - Object with fields to add
   */
  withStructured(data: Record<string, unknown>): this;
  withStructured(keyOrData: string | Record<string, unknown>, value?: unknown): this {
    if (typeof keyOrData === 'string') {
      this.structured[keyOrData] = value;
    } else {
      Object.assign(this.structured, keyOrData);
    }
    return this;
  }

  /**
   * Set the subject
   * @param subject - Subject text
   */
  withSubject(subject: string): this {
    this.subject = subject;
    return this;
  }

  /**
   * Set the body
   * @param body - Body text
   */
  withBody(body: string): this {
    this.body = body;
    return this;
  }

  /**
   * Set the expiration
   * @param expiresAt - Expiration date/time
   */
  withExpiration(expiresAt: Date | string): this {
    this.expiresAt = expiresAt;
    return this;
  }

  async #encryptFile(input: FileInput): Promise<FileEncryptionResult> {
    let fileData: Buffer;
    if (input.buffer) {
      fileData = input.buffer;
    } else if (input.path) {
      fileData = readFileAt(input.path);
    } else {
      throw buildFailed('FILE_SOURCE_MISSING', 'File input must have either path or buffer');
    }

    if (fileData.length === 0) {
      throw buildFailed('EMPTY_FILE', `File "${input.filename}" is empty`);
    }

    const originalSize = fileData.length;
    const shouldCompressFile = input.compress !== false && shouldCompress(originalSize);

    let dataToEncrypt = fileData;
    let compressed = false;
    let compressionAlgorithm: 'gzip' | undefined;

    if (shouldCompressFile) {
      const compressionResult = await compressData(fileData);
      dataToEncrypt = compressionResult.compressedData;
      compressed = true;
      compressionAlgorithm = 'gzip';
    }

    const raw = encryptAESRaw(dataToEncrypt, this.#masterKey);
    const hash = computeHash(raw.encryptedData);
    const contentIV = raw.iv.toString('base64url');
    const authTag = raw.authTag.toString('base64url');
    const mimetype = input.mimetype || (input.path && lookupMimeType(input.path)) || 'application/octet-stream';

    return {
      encryptedData: raw.encryptedData,
      iv: contentIV,
      authTag,
      hash,
      size: raw.encryptedData.length,
      mimetype,
      ...(compressed && { compressed }),
      ...(compressionAlgorithm && { compressionAlgorithm }),
      ...(compressed && { originalSize }),
    };
  }

  getRecipientIds(): string[] {
    return this.#recipients.map((r) => r.partyId);
  }

  getFileCount(): number {
    return this.#files.length;
  }


  /**
   * Build the capsa with encryption and signature.
   * @param partyKeys - Public keys for the creator, the recipient and its delegates
   *   (other parties in the list are ignored)
   */
  async build(partyKeys: PartyKey[]): Promise<BuiltCapsa> {
    const principal = this.#recipients[0];
    if (!principal) {
      throw buildFailed('NO_RECIPIENT', NO_RECIPIENT_MESSAGE);
    }

    // No-content guard: server requires files OR a message (subject/body)
    const hasContent = this.#files.length > 0 || this.subject || this.body;
    if (!hasContent) {
      throw buildFailed('NO_CONTENT',
        'Capsa must contain either files or a message (subject/body). Server will reject empty capsas.'
      );
    }

    if (!this.#expiresAt) {
      throw buildFailed('EXPIRATION_REQUIRED',
        'Expiration is required. Call withExpiration() with the date this capsa should ' +
        'expire, based on how long the record needs to be retained.'
      );
    }

    const now = Date.now();
    const maxDays = maxExpirationDays(this.#limits);
    const latestExpiry = now + maxDays * DAY_MS;
    const capsaExpiry = new Date(this.#expiresAt).getTime();
    if (capsaExpiry <= now) {
      throw buildFailed('EXPIRATION_IN_PAST',
        `Expiration ${this.#expiresAt} is in the past. Set an expiration after the current time.`
      );
    }
    if (capsaExpiry > latestExpiry) {
      throw buildFailed('EXPIRATION_TOO_FAR',
        `Expiration ${this.#expiresAt} is more than ${maxDays} days in the future. The latest allowed expiration is ${maxDays} days from now.`
      );
    }

    const principalKey = partyKeys.find((key) => key.id === principal.partyId);
    if (!principalKey?.publicKey) {
      throw new CapsaraError(
        `Recipient ${principal.partyId} has no registered public key`,
        'RECIPIENT_KEY_NOT_FOUND',
        0,
        { partyId: principal.partyId }
      );
    }

    const packageId = `capsa_${generateId(22)}`;
    const encryptedFiles: Array<{ metadata: EncryptedFile; data: Buffer }> = [];
    let totalSize = 0;

    for (const file of this.#files) {
      const encrypted = await this.#encryptFile(file.input);
      const { encryptedData: encryptedFilename, iv: filenameIV, authTag: filenameAuthTag } = encryptAES(
        Buffer.from(file.input.filename, 'utf-8'),
        this.#masterKey
      );

      if (encryptedFilename.length > SERVER_LIMITS.MAX_ENCRYPTED_FILENAME) {
        throw buildFailed('FILENAME_TOO_LONG',
          `Encrypted filename for "${file.input.filename.slice(0, 30)}..." (${encryptedFilename.length} chars) exceeds server limit of ${SERVER_LIMITS.MAX_ENCRYPTED_FILENAME} chars. Use a shorter filename.`
        );
      }

      let normalizedFileExpiresAt: string | undefined;
      if (file.input.expiresAt !== undefined) {
        const dateObj = typeof file.input.expiresAt === 'string'
          ? new Date(file.input.expiresAt)
          : new Date(file.input.expiresAt.getTime());
        if (Number.isNaN(dateObj.getTime())) {
          throw buildFailed('INVALID_FILE_EXPIRATION',
            `Expiration for "${file.input.filename}" is not a valid date: ${String(file.input.expiresAt)}`
          );
        }
        dateObj.setSeconds(0, 0);
        normalizedFileExpiresAt = dateObj.toISOString();

        if (dateObj.getTime() <= now) {
          throw buildFailed('FILE_EXPIRATION_IN_PAST',
            `Expiration for "${file.input.filename}" (${normalizedFileExpiresAt}) is in the past. Set an expiration after the current time.`
          );
        }
        if (dateObj.getTime() > latestExpiry) {
          throw buildFailed('FILE_EXPIRATION_TOO_FAR',
            `Expiration for "${file.input.filename}" (${normalizedFileExpiresAt}) is more than ${maxDays} days in the future. ` +
            `The latest allowed expiration is ${maxDays} days from now.`
          );
        }
        if (dateObj.getTime() > capsaExpiry) {
          throw buildFailed('FILE_OUTLIVES_CAPSA',
            `Expiration for "${file.input.filename}" (${normalizedFileExpiresAt}) is after the capsa ` +
            `expires (${this.#expiresAt}). A file cannot outlive the capsa that carries it.`
          );
        }
      }

      const fileMetadata: EncryptedFile = {
        fileId: `file_${generateId(16)}.enc`,
        encryptedFilename,
        filenameIV,
        filenameAuthTag,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        mimetype: encrypted.mimetype,
        size: encrypted.size,
        hash: encrypted.hash,
        hashAlgorithm: 'SHA-256',
        ...(encrypted.compressed !== undefined && { compressed: encrypted.compressed }),
        ...(encrypted.compressionAlgorithm && { compressionAlgorithm: encrypted.compressionAlgorithm }),
        ...(encrypted.originalSize !== undefined && { originalSize: encrypted.originalSize }),
        ...(normalizedFileExpiresAt !== undefined && { expiresAt: normalizedFileExpiresAt }),
        ...(file.input.transform && { transform: file.input.transform }),
      };

      encryptedFiles.push({
        metadata: fileMetadata,
        data: encrypted.encryptedData,
      });

      totalSize += encrypted.size;
    }

    if (totalSize > this.#limits.maxTotalSize) {
      throw buildFailed('TOTAL_SIZE_EXCEEDED',
        `Total capsa size ${totalSize} bytes exceeds maximum of ${Math.floor(this.#limits.maxTotalSize / 1024 / 1024)}MB`
      );
    }

    let encryptedSubject: string | undefined;
    let subjectIV: string | undefined;
    let subjectAuthTag: string | undefined;
    let encryptedBody: string | undefined;
    let bodyIV: string | undefined;
    let bodyAuthTag: string | undefined;
    let encryptedStructured: string | undefined;
    let structuredIV: string | undefined;
    let structuredAuthTag: string | undefined;

    if (this.subject) {
      const result = encryptAES(
        Buffer.from(this.subject, 'utf-8'),
        this.#masterKey
      );
      encryptedSubject = result.encryptedData;
      subjectIV = result.iv;
      subjectAuthTag = result.authTag;

      if (encryptedSubject.length > SERVER_LIMITS.MAX_ENCRYPTED_SUBJECT) {
        throw buildFailed('SUBJECT_TOO_LARGE',
          `Encrypted subject (${encryptedSubject.length} chars) exceeds server limit of ${SERVER_LIMITS.MAX_ENCRYPTED_SUBJECT} chars. Reduce subject length.`
        );
      }
    }

    if (this.body) {
      const result = encryptAES(
        Buffer.from(this.body, 'utf-8'),
        this.#masterKey
      );
      encryptedBody = result.encryptedData;
      bodyIV = result.iv;
      bodyAuthTag = result.authTag;

      if (encryptedBody.length > SERVER_LIMITS.MAX_ENCRYPTED_BODY) {
        throw buildFailed('BODY_TOO_LARGE',
          `Encrypted body (${encryptedBody.length} chars) exceeds server limit of ${SERVER_LIMITS.MAX_ENCRYPTED_BODY} chars. Reduce body length.`
        );
      }
    }

    const hasStructured = Object.keys(this.structured).length > 0;
    if (hasStructured) {
      const result = encryptAES(
        Buffer.from(JSON.stringify(this.structured), 'utf-8'),
        this.#masterKey
      );
      encryptedStructured = result.encryptedData;
      structuredIV = result.iv;
      structuredAuthTag = result.authTag;

      if (encryptedStructured.length > SERVER_LIMITS.MAX_ENCRYPTED_STRUCTURED) {
        throw buildFailed('STRUCTURED_TOO_LARGE',
          `Encrypted structured data (${encryptedStructured.length} chars) exceeds server limit of ${SERVER_LIMITS.MAX_ENCRYPTED_STRUCTURED} chars. Reduce structured data size.`
        );
      }
    }

    const keychain: KeychainEntry[] = [];

    for (const partyKey of partyKeys) {
      const isCreator = partyKey.id === this.#creatorId;
      const isPrincipal = partyKey.id === principal.partyId;
      // A delegate is included only when it acts for this capsa's recipient, and
      // then only on that recipient's behalf.
      const actsForPrincipal =
        !isPrincipal &&
        Array.isArray(partyKey.isDelegate) &&
        partyKey.isDelegate.includes(principal.partyId);
      let permissions: string[];
      let actingFor: string[] | undefined;

      if (actsForPrincipal) {
        permissions = ['delegate'];
        actingFor = [principal.partyId];
      } else if (isCreator) {
        permissions = [];
      } else if (isPrincipal) {
        permissions = principal.permissions;
      } else {
        continue;
      }

      const isDelegatedRecipient = permissions.length === 0 && !isCreator;

      const keyIV = generateIV();

      keychain.push({
        party: partyKey.id,
        encryptedKey: isDelegatedRecipient
          ? ''
          : encryptMasterKeyForParty(this.#masterKey, partyKey.publicKey),
        iv: keyIV,
        fingerprint: partyKey.fingerprint,
        permissions,
        actingFor,
      });
    }

    if (keychain.length > SERVER_LIMITS.MAX_KEYCHAIN_KEYS) {
      throw buildFailed('TOO_MANY_KEYCHAIN_ENTRIES',
        `Keychain has ${keychain.length} entries (creator, recipient and delegates), exceeding the server limit of ${SERVER_LIMITS.MAX_KEYCHAIN_KEYS}.`
      );
    }

    const canonicalString = buildCanonicalString({
      packageId,
      totalSize,
      algorithm: 'AES-256-GCM',
      creatorPartyId: this.#creatorId,
      creatorKeyFingerprint: calculatePrivateKeyFingerprint(this.#creatorPrivateKey),
      files: encryptedFiles.map((f) => f.metadata),
      structuredIV,
      subjectIV,
      bodyIV,
    });

    const signature = createCapsaSignature(
      canonicalString,
      this.#creatorPrivateKey
    );

    if (signature.payload.length > SERVER_LIMITS.MAX_SIGNATURE_PAYLOAD) {
      throw buildFailed('SIGNATURE_TOO_LARGE',
        `Signature payload (${signature.payload.length} chars) exceeds server limit of ${SERVER_LIMITS.MAX_SIGNATURE_PAYLOAD} chars.`
      );
    }

    const capsa: Partial<Capsa> & {
      packageId: string;
      keychain: { algorithm: string; keys: KeychainEntry[] };
      signature: { algorithm: string; protected: string; payload: string; signature: string };
      accessControl: { expiresAt?: string };
      deliveryPriority: string;
      files: EncryptedFile[];
      metadata?: CapsaMetadata;
      encryptedSubject?: string;
      subjectIV?: string;
      subjectAuthTag?: string;
      encryptedBody?: string;
      bodyIV?: string;
      bodyAuthTag?: string;
      encryptedStructured?: string;
      structuredIV?: string;
      structuredAuthTag?: string;
    } = {
      packageId,
      keychain: {
        algorithm: 'AES-256-GCM',
        keys: keychain,
      },
      signature,
      files: encryptedFiles.map((f) => f.metadata),
      accessControl: {
        expiresAt: this.#expiresAt,
      },
      deliveryPriority: 'normal',
    };

    const hasMetadata = this.metadata.label || this.metadata.tags?.length || this.metadata.notes || this.metadata.relatedPackages?.length;
    if (hasMetadata) {
      if (this.metadata.label && this.metadata.label.length > SERVER_LIMITS.MAX_METADATA_LABEL) {
        throw buildFailed('METADATA_LABEL_TOO_LONG',
          `Metadata label (${this.metadata.label.length} chars) exceeds server limit of ${SERVER_LIMITS.MAX_METADATA_LABEL} chars.`
        );
      }
      if (this.metadata.tags && this.metadata.tags.length > SERVER_LIMITS.MAX_METADATA_TAGS) {
        throw buildFailed('TOO_MANY_TAGS',
          `Metadata tags count (${this.metadata.tags.length}) exceeds server limit of ${SERVER_LIMITS.MAX_METADATA_TAGS}.`
        );
      }
      if (this.metadata.tags) {
        for (const tag of this.metadata.tags) {
          if (tag.length > SERVER_LIMITS.MAX_TAG_LENGTH) {
            throw buildFailed('TAG_TOO_LONG',
              `Metadata tag "${tag.slice(0, 20)}..." (${tag.length} chars) exceeds server limit of ${SERVER_LIMITS.MAX_TAG_LENGTH} chars.`
            );
          }
        }
      }
      if (this.metadata.notes && this.metadata.notes.length > SERVER_LIMITS.MAX_METADATA_NOTES) {
        throw buildFailed('METADATA_NOTES_TOO_LONG',
          `Metadata notes (${this.metadata.notes.length} chars) exceeds server limit of ${SERVER_LIMITS.MAX_METADATA_NOTES} chars.`
        );
      }
      if (this.metadata.relatedPackages && this.metadata.relatedPackages.length > SERVER_LIMITS.MAX_RELATED_PACKAGES) {
        throw buildFailed('TOO_MANY_RELATED_PACKAGES',
          `Related packages count (${this.metadata.relatedPackages.length}) exceeds server limit of ${SERVER_LIMITS.MAX_RELATED_PACKAGES}.`
        );
      }
      capsa.metadata = this.metadata;
    }

    if (encryptedSubject) {
      capsa.encryptedSubject = encryptedSubject;
      capsa.subjectIV = subjectIV;
      capsa.subjectAuthTag = subjectAuthTag;
    }
    if (encryptedBody) {
      capsa.encryptedBody = encryptedBody;
      capsa.bodyIV = bodyIV;
      capsa.bodyAuthTag = bodyAuthTag;
    }
    if (encryptedStructured) {
      capsa.encryptedStructured = encryptedStructured;
      capsa.structuredIV = structuredIV;
      capsa.structuredAuthTag = structuredAuthTag;
    }

    const capsaJsonBytes = Buffer.byteLength(JSON.stringify(capsa), 'utf8');
    if (capsaJsonBytes > SERVER_LIMITS.MAX_JSON_FIELD) {
      throw buildFailed('CAPSA_JSON_TOO_LARGE',
        `Capsa metadata (${capsaJsonBytes} bytes) exceeds the server limit of ${SERVER_LIMITS.MAX_JSON_FIELD} bytes per JSON field. ` +
        'Reduce the body, structured data or metadata.'
      );
    }

    // Defense-in-depth: detect duplicate IVs across all fields.
    // Server performs the same check and will reject duplicates.
    const allIVs: string[] = [];
    if (subjectIV) allIVs.push(subjectIV);
    if (bodyIV) allIVs.push(bodyIV);
    if (structuredIV) allIVs.push(structuredIV);
    for (const entry of keychain) {
      if (entry.iv) allIVs.push(entry.iv);
    }
    for (const file of encryptedFiles) {
      allIVs.push(file.metadata.iv);
      allIVs.push(file.metadata.filenameIV);
    }
    const ivSet = new Set(allIVs);
    if (ivSet.size !== allIVs.length) {
      throw buildFailed('DUPLICATE_IV',
        'Duplicate IV detected across capsa fields. This indicates a CSPRNG failure. Do not send this capsa.'
      );
    }

    return { capsa, files: encryptedFiles };
  }
}
