import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { getFilePermissionFact } from '../../src/discovery/permissions.js';

// File permission bits are set at test time via chmod rather than relying on
// a committed mode: git only preserves the executable bit, so a fixture
// checked out through git (and possibly through a different umask) cannot
// reliably reproduce e.g. 0600 vs 0644 across machines/CI.
describe('getFilePermissionFact', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-perm-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('reports a group/other-readable file as such', () => {
    const filePath = path.join(dir, 'config.yaml');
    writeFileSync(filePath, 'a: 1\n', { mode: 0o644 });

    const fact = getFilePermissionFact(filePath);

    expect(fact.exists).toBe(true);
    expect(fact.mode).toBe(0o644);
    expect(fact.groupOrOtherReadable).toBe(true);
  });

  it('reports an owner-only file as not group/other-readable', () => {
    const filePath = path.join(dir, 'config.yaml');
    writeFileSync(filePath, 'a: 1\n', { mode: 0o600 });

    const fact = getFilePermissionFact(filePath);

    expect(fact.mode).toBe(0o600);
    expect(fact.groupOrOtherReadable).toBe(false);
    expect(fact.groupOrOtherWritable).toBe(false);
  });

  it('degrades gracefully for a missing file instead of throwing', () => {
    const fact = getFilePermissionFact(path.join(dir, 'does-not-exist.yaml'));

    expect(fact.exists).toBe(false);
    expect(fact.mode).toBeNull();
    expect(fact.groupOrOtherReadable).toBeNull();
  });
});
