import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadChaperoneConfig } from '../../src/config/chaperoneConfig.js';
import { writeStarterConfig } from '../../src/config/initConfig.js';

// PROPOSED_FIXES.md 7.4.1.
describe('writeStarterConfig', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-init-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('writes a starter config that loads cleanly', () => {
    const file = writeStarterConfig(dir);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toHaveProperty('//ignore');
    expect(loadChaperoneConfig(file).config).toEqual({
      severityOverrides: {},
      ignore: [],
      disabledChecks: [],
      plugins: [],
    });
  });

  it('refuses to overwrite an existing file', () => {
    writeFileSync(path.join(dir, '.chaperonerc.json'), '{"keep": true}');
    expect(() => writeStarterConfig(dir)).toThrow(/already exists/);
    expect(readFileSync(path.join(dir, '.chaperonerc.json'), 'utf8')).toBe('{"keep": true}');
  });
});
