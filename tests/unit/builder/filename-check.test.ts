/**
 * Builder file name check, run against the shared safe file name vectors.
 * @file tests/unit/builder/filename-check.test.ts
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { CapsaBuilder } from '../../../src/builder/capsa-builder.js';
import { CapsaraError } from '../../../src/errors/capsara-error.js';
import type { SystemLimits } from '../../../src/types/index.js';

interface Vector {
  name: string;
  input: string;
  expected: string;
  rejectOnSend: boolean;
}

const fixturePath = fileURLToPath(new URL('../../fixtures/safe-filename-vectors.json', import.meta.url));
const { vectors } = JSON.parse(readFileSync(fixturePath, 'utf-8')) as { vectors: Vector[] };

const limits: SystemLimits = {
  maxFileSize: 50 * 1024 * 1024,
  maxFilesPerCapsa: 100,
  maxTotalSize: 500 * 1024 * 1024,
};

function newBuilder(): CapsaBuilder {
  return new CapsaBuilder('party_creator', 'unused-private-key', limits);
}

function catchError(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

describe('CapsaBuilder file name check', () => {
  it.each(vectors.map((v) => [v.name, v] as const))('%s', (_name, vector) => {
    const error = catchError(() => newBuilder().addFileFromBuffer(Buffer.from('x'), vector.input));
    if (vector.rejectOnSend) {
      expect(error).toBeInstanceOf(CapsaraError);
      expect((error as CapsaraError).code).toBe('VALIDATION_ERROR');
    } else {
      expect(error).toBeUndefined();
    }
  });

  it('does not echo the rejected name in the message', () => {
    const error = catchError(() => newBuilder().addFileFromBuffer(Buffer.from('x'), '../../.ssh/authorized_keys'));
    expect(error).toBeInstanceOf(CapsaraError);
    expect((error as CapsaraError).message).not.toContain('authorized_keys');
    expect((error as CapsaraError).message).toMatch(/path separator/);
  });

  it('rejects before adding the file', () => {
    const builder = newBuilder();
    expect(() => builder.addTextFile('../x.txt', 'content')).toThrow(CapsaraError);
    expect(builder.getFileCount()).toBe(0);
  });

  it('checks every add-file entry point', () => {
    expect(() => newBuilder().addFile({ buffer: Buffer.from('x'), filename: '../x.txt' })).toThrow(CapsaraError);
    expect(() => newBuilder().addTextFile('a/b.txt', 'x')).toThrow(CapsaraError);
    expect(() => newBuilder().addJsonFile('a\\b.json', {})).toThrow(CapsaraError);
    expect(() => newBuilder().addFilesFromInputs({ buffer: Buffer.from('x'), filename: '..' })).toThrow(CapsaraError);
    expect(() => newBuilder().addFileFromPath(fixturePath, '../x.txt')).toThrow(CapsaraError);
  });

  it('takes the file name part of a path', () => {
    const builder = newBuilder();
    builder.addFileFromPath(fixturePath);
    builder.addFiles(fixturePath);
    expect(builder.getFileCount()).toBe(2);
  });
});
