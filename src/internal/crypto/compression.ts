/** Gzip compression/decompression applied before encryption. */

import * as zlib from 'zlib';
import { promisify } from 'util';

const gzipAsync = promisify(zlib.gzip);
const gunzipAsync = promisify(zlib.gunzip);

export interface CompressionResult {
  compressedData: Buffer;
  originalSize: number;
  compressedSize: number;
}

/** Compress data using gzip. */
export async function compressData(data: Buffer): Promise<CompressionResult> {
  const originalSize = data.length;
  const compressedData = await gzipAsync(data, {
    level: zlib.constants.Z_DEFAULT_COMPRESSION, // Balance between speed and compression
  });

  return {
    compressedData,
    originalSize,
    compressedSize: compressedData.length,
  };
}

/** @throws Error if decompression fails */
export async function decompressData(data: Buffer): Promise<Buffer> {
  try {
    return await gunzipAsync(data);
  } catch (error) {
    throw new Error(`Failed to decompress data: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Files smaller than 150 bytes don't benefit from compression (gzip header overhead breakeven).
 */
export function shouldCompress(size: number): boolean {
  const MIN_COMPRESSION_SIZE = 150; // 150 bytes (gzip header overhead breakeven point)
  return size >= MIN_COMPRESSION_SIZE;
}
