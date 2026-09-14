import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSec003PermissiveFilePermissions } from '../../src/checks/secrets/chapSec003PermissiveFilePermissions.js';
import { discoverAgent } from '../../src/discovery/index.js';

// Permission bits are set at test time via chmod rather than relying on the
// named fixtures' committed mode — git only preserves the executable bit,
// so a fixture checked out via git (and a different umask) can't reliably
// reproduce 0600 vs 0644 across machines/CI. See DECISIONS.md, Phase 1/3.
describe('CHAP-SEC-003 — overly permissive file permissions', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sec003-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('fires when the config file is group/other-readable', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  provider: anthropic\n', { mode: 0o644 });

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSec003PermissiveFilePermissions.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-SEC-003');
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.location.detail).toBe('mode 644');
  });

  it('stays silent when the config file is owner-only (0600)', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  provider: anthropic\n', { mode: 0o600 });

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec003PermissiveFilePermissions.run(model)).toEqual([]);
  });

  it('stays silent when there is no config file to check', () => {
    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec003PermissiveFilePermissions.run(model)).toEqual([]);
  });
});
