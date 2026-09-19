import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSec006SidecarSecretFileExposed } from '../../src/checks/secrets/chapSec006SidecarSecretFileExposed.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SEC-006 — sidecar secret file exposed', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sec006-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('fires when a sidecar file holds a literal secret, is git-tracked and not gitignored', () => {
    mkdirSync(path.join(dir, '.git'));
    writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n');
    writeFileSync(path.join(dir, 'secrets.yaml'), 'api_key: sk-dummy-literal-value\n', {
      mode: 0o600,
    });

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSec006SidecarSecretFileExposed.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-SEC-006');
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.message).toContain('git repository');
    expect(findings[0]?.message).not.toContain('readable by group or other');
  });

  it('fires when a sidecar file holds a literal secret and is group/other-readable', () => {
    writeFileSync(path.join(dir, '.env'), 'API_KEY=sk-dummy-literal-value\n', { mode: 0o644 });

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSec006SidecarSecretFileExposed.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('readable by group or other');
    expect(findings[0]?.message).not.toContain('git repository');
  });

  it('combines both reasons into one finding when both hold', () => {
    mkdirSync(path.join(dir, '.git'));
    writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n');
    writeFileSync(path.join(dir, '.env'), 'API_KEY=sk-dummy-literal-value\n', { mode: 0o644 });

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSec006SidecarSecretFileExposed.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('git repository');
    expect(findings[0]?.message).toContain('readable by group or other');
  });

  it('stays silent when the secret is covered by .gitignore and owner-only permissioned', () => {
    mkdirSync(path.join(dir, '.git'));
    writeFileSync(path.join(dir, '.gitignore'), 'secrets.yaml\n');
    writeFileSync(path.join(dir, 'secrets.yaml'), 'api_key: sk-dummy-literal-value\n', {
      mode: 0o600,
    });

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec006SidecarSecretFileExposed.run(model)).toEqual([]);
  });

  it('stays silent when the sidecar file only holds env-var references, not literals', () => {
    writeFileSync(path.join(dir, '.env'), 'API_KEY=${OPENAI_API_KEY}\n', { mode: 0o644 });

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec006SidecarSecretFileExposed.run(model)).toEqual([]);
  });

  it('stays silent when no sidecar secret file exists at all', () => {
    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec006SidecarSecretFileExposed.run(model)).toEqual([]);
  });
});
