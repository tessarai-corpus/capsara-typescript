/**
 * Safe file names for received files.
 *
 * A received file's name is decrypted from what the sender supplied, so it is
 * untrusted: it can hold path separators, control characters or names that
 * Windows reserves. sanitizeFilename turns any name into a single path segment
 * that is safe to join to a directory of the caller's choosing.
 */

/** Maximum UTF-8 bytes of a safe file name. */
const MAX_FILENAME_BYTES = 255;

/** Longest extension, in UTF-8 bytes including the dot, kept when a name is cut. */
const MAX_EXTENSION_BYTES = 32;

const FALLBACK_FILENAME = 'file';

const WINDOWS_INVALID = new Set(['<', '>', ':', '"', '|', '?', '*']);

const RESERVED_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
]);

/** Whether a code point is a control character (U+0000 to U+001F, or U+007F). */
export function isControl(codePoint: number): boolean {
  return codePoint <= 0x1f || codePoint === 0x7f;
}

function utf8Length(codePoint: number): number {
  if (codePoint < 0x80) return 1;
  if (codePoint < 0x800) return 2;
  if (codePoint < 0x10000) return 3;
  return 4;
}

function utf8ByteLength(value: string): number {
  let total = 0;
  for (const ch of value) {
    total += utf8Length(ch.codePointAt(0) ?? 0);
  }
  return total;
}

function trimStartSpaces(value: string): string {
  let start = 0;
  while (start < value.length && value[start] === ' ') start++;
  return value.slice(start);
}

function trimEndSpacesAndDots(value: string): string {
  let end = value.length;
  while (end > 0 && (value[end - 1] === ' ' || value[end - 1] === '.')) end--;
  return value.slice(0, end);
}

function isReserved(name: string): boolean {
  const dot = name.indexOf('.');
  let stem = dot === -1 ? name : name.slice(0, dot);
  let end = stem.length;
  while (end > 0 && stem[end - 1] === ' ') end--;
  stem = stem.slice(0, end);
  return RESERVED_NAMES.has(stem.replace(/[a-z]/g, (c) => c.toUpperCase()));
}

/** Longest prefix of whole code points whose UTF-8 form fits in maxBytes. */
function truncateUtf8(value: string, maxBytes: number): string {
  let used = 0;
  let out = '';
  for (const ch of value) {
    const size = utf8Length(ch.codePointAt(0) ?? 0);
    if (used + size > maxBytes) break;
    used += size;
    out += ch;
  }
  return out;
}

function capLength(name: string, maxBytes: number): string {
  if (utf8ByteLength(name) <= maxBytes) return name;
  let stem = name;
  let extension = '';
  const dot = name.lastIndexOf('.');
  if (dot > 0) {
    const candidate = name.slice(dot);
    if (utf8ByteLength(candidate) <= MAX_EXTENSION_BYTES) {
      extension = candidate;
      stem = name.slice(0, dot);
    }
  }
  stem = trimEndSpacesAndDots(truncateUtf8(stem, maxBytes - utf8ByteLength(extension)));
  return stem + extension;
}

/**
 * Turn an untrusted file name into a safe single path segment.
 *
 * Rules, applied in order:
 * 1. Keep only the part after the last "/" or "\".
 * 2. Remove control characters (U+0000 to U+001F and U+007F).
 * 3. Replace the characters Windows does not allow (< > : " | ? *) with "_".
 * 4. Trim leading and trailing spaces, and trailing dots.
 * 5. Cap the name at 255 UTF-8 bytes, keeping an extension of up to 32 bytes
 *    and never splitting a character.
 * 6. Use "file" for an empty result, and prefix "_" to ".", "..", and Windows
 *    reserved device names (CON, PRN, AUX, NUL, COM1 to COM9, LPT1 to LPT9, in
 *    any case, with or without an extension).
 *
 * The result is never empty, holds no path separator, and is at most 255 UTF-8
 * bytes. It is a name only: join it to a directory you chose.
 * @param name - The untrusted file name
 * @returns A safe file name
 */
export function sanitizeFilename(name: string): string {
  const lastSeparator = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
  let result = '';
  for (const ch of name.slice(lastSeparator + 1)) {
    if (isControl(ch.codePointAt(0) ?? 0)) continue;
    result += WINDOWS_INVALID.has(ch) ? '_' : ch;
  }
  result = trimEndSpacesAndDots(trimStartSpaces(result));
  result = capLength(result, MAX_FILENAME_BYTES);

  if (result.length === 0) return FALLBACK_FILENAME;
  if (result === '.' || result === '..' || isReserved(result)) {
    return `_${capLength(result, MAX_FILENAME_BYTES - 1)}`;
  }
  return result;
}
