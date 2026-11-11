/**
 * Multipart form-data builder for capsa upload
 * @file capsara.sdk/typescript/src/internal/upload/multipart-builder.ts
 */

import * as crypto from 'crypto';
import type { MultipartPart, EncryptedFile } from '../types.js';

/**
 * Multipart form-data builder for capsa uploads (supports 1-500 capsas)
 */
export class CapsasMultipartBuilder {
  private boundary: string;
  private parts: MultipartPart[] = [];
  private metadataSet: boolean = false;

  constructor() {
    // Generate unique boundary
    this.boundary = `----CapsaBoundary${crypto.randomBytes(16).toString("hex")}`;
  }

  /**
   * Add capsa metadata (must be first)
   * @param capsaCount - Number of capsas in request
   * @param creator - Creator party ID
   */
  addMetadata(capsaCount: number, creator: string): this {
    if (this.metadataSet) {
      throw new Error('Metadata already set');
    }

    this.parts.push({
      name: 'metadata',
      content: JSON.stringify({ capsaCount, creator }),
      contentType: 'application/json',
    });

    this.metadataSet = true;
    return this;
  }

  /**
   * Add capsa metadata part with index
   * @param capsa - Capsa object
   * @param capsaIndex - Capsa index in request
   */
  addCapsaMetadata(capsa: unknown, capsaIndex: number): this {
    if (!this.metadataSet) {
      throw new Error('Must call addMetadata() first');
    }

    this.parts.push({
      name: `capsa_${capsaIndex}`,
      content: JSON.stringify(capsa),
      contentType: 'application/json',
    });
    return this;
  }

  /**
   * Add file metadata part with capsa and file indexes
   * @param fileMetadata - File metadata object with fileId
   * @param capsaIndex - Capsa index
   * @param fileIndex - File index within capsa
   */
  addFileMetadata(
    fileMetadata: EncryptedFile | (Record<string, unknown> & { fileId?: string }),
    capsaIndex: number,
    fileIndex: number
  ): this {
    if (!this.metadataSet) {
      throw new Error('Must call addMetadata() first');
    }

    const fileId = fileMetadata.fileId || `file_${capsaIndex}_${fileIndex}`;

    this.parts.push({
      name: 'file',
      content: JSON.stringify(fileMetadata),
      contentType: 'application/json',
      filename: `${fileId}.json`,
    });
    return this;
  }

  /**
   * Add file binary part with file ID
   * @param fileData - File data buffer
   * @param fileId - File ID from metadata (should include .enc extension)
   */
  addFileBinary(fileData: Buffer, fileId: string): this {
    if (!this.metadataSet) {
      throw new Error('Must call addMetadata() first');
    }

    this.parts.push({
      name: 'file',
      content: fileData,
      contentType: 'application/octet-stream',
      filename: fileId,  // Use fileId directly (already includes .enc)
    });
    return this;
  }

  /**
   * Build the complete multipart body
   * @returns Multipart body as Buffer
   */
  build(): Buffer {
    if (!this.metadataSet) {
      throw new Error('Must call addMetadata() first');
    }

    const chunks: Buffer[] = [];

    for (const part of this.parts) {
      // Add boundary
      chunks.push(Buffer.from(`--${this.boundary}\r\n`, 'utf-8'));

      // Add Content-Disposition header
      let disposition = `Content-Disposition: form-data; name="${part.name}"`;
      if (part.filename) {
        disposition += `; filename="${part.filename}"`;
      }
      chunks.push(Buffer.from(disposition + '\r\n', 'utf-8'));

      // Add Content-Type header
      if (part.contentType) {
        chunks.push(
          Buffer.from(`Content-Type: ${part.contentType}\r\n`, 'utf-8')
        );
      }

      // Add blank line
      chunks.push(Buffer.from('\r\n', 'utf-8'));

      // Add content
      if (typeof part.content === 'string') {
        chunks.push(Buffer.from(part.content, 'utf-8'));
      } else {
        chunks.push(part.content);
      }

      // Add trailing line break
      chunks.push(Buffer.from('\r\n', 'utf-8'));
    }

    // Add final boundary
    chunks.push(Buffer.from(`--${this.boundary}--\r\n`, 'utf-8'));

    return Buffer.concat(chunks);
  }

  /**
   * Get the Content-Type header value
   * @returns Content-Type with boundary
   */
  getContentType(): string {
    return `multipart/form-data; boundary=${this.boundary}`;
  }

  /**
   * Get the boundary string
   * @returns Boundary string
   */
  getBoundary(): string {
    return this.boundary;
  }
}
