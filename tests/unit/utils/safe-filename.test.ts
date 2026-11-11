/**
 * Shared safe file name vectors, run against sanitizeFilename.
 * @file tests/unit/utils/safe-filename.test.ts
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { sanitizeFilename } from '../../../src/index.js';

interface Vector {
  name: string;
  input: string;
  expected: string;
  rejectOnSend: boolean;
}

const fixturePath = fileURLToPath(new URL('../../fixtures/safe-filename-vectors.json', import.meta.url));
const { vectors } = JSON.parse(readFileSync(fixturePath, 'utf-8')) as { vectors: Vector[] };

describe('sanitizeFilename', () => {
  it('loads the shared vectors', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(25);
  });

  it.each(vectors.map((v) => [v.name, v] as const))('%s', (_name, vector) => {
    const result = sanitizeFilename(vector.input);
    expect(result).toBe(vector.expected);
    expect(Buffer.byteLength(result, 'utf-8')).toBeLessThanOrEqual(255);
  });

  it.each(vectors.map((v) => [v.name, v] as const))('stays inside the target directory: %s', (_name, vector) => {
    const dir = path.resolve(os.tmpdir(), 'capsara-downloads');
    const target = path.resolve(dir, sanitizeFilename(vector.input));
    expect(path.dirname(target)).toBe(dir);
  });
});
