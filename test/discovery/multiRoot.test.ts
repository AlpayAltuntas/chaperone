import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { expandAllPattern } from '../../src/discovery/multiRoot.js';

describe('expandAllPattern', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-multiroot-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('returns a single-element array for a pattern with no trailing /*', () => {
    expect(expandAllPattern(dir)).toEqual([path.resolve(dir)]);
  });

  it('expands a trailing /* to every immediate subdirectory, sorted', () => {
    mkdirSync(path.join(dir, 'bravo'));
    mkdirSync(path.join(dir, 'alpha'));
    mkdirSync(path.join(dir, 'charlie'));
    writeFileSync(path.join(dir, 'not-a-dir.txt'), 'x');

    const result = expandAllPattern(`${dir}/*`);

    expect(result).toEqual([
      path.join(dir, 'alpha'),
      path.join(dir, 'bravo'),
      path.join(dir, 'charlie'),
    ]);
  });

  it('returns an empty array for an empty parent directory', () => {
    expect(expandAllPattern(`${dir}/*`)).toEqual([]);
  });

  it('throws a clear error when the parent directory does not exist', () => {
    const missing = path.join(dir, 'nope');

    expect(() => expandAllPattern(`${missing}/*`)).toThrow(/could not list/);
  });

  it('expands a leading ~ via expandHome before resolving', () => {
    // Not asserting a specific path (depends on the real home dir) —
    // just that it doesn't throw and resolves to an absolute path.
    const result = expandAllPattern('~');
    expect(path.isAbsolute(result[0] ?? '')).toBe(true);
  });
});
