// Cryptographically secure, unbiased ID generator using a 64-char URL-safe alphabet.
import { randomBytes } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';

/**
 * @param size - Length of the ID (default 21, ~126 bits of entropy)
 * @returns URL-safe random ID string
 */
export function nanoid(size = 21): string {
  const bytes = randomBytes(size);
  let id = '';

  for (let i = 0; i < size; i++) {
    // Bitmask with 0x3F (63) gives uniform distribution for 64-char alphabet
    // Each of 256 byte values maps to exactly 4 alphabet characters (256/64 = 4)
    id += ALPHABET[bytes[i]! & 0x3f];
  }

  return id;
}

/** @deprecated Use nanoid() instead */
export const generateId = nanoid;