import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapObs004MemoryStoreExposed } from '../../src/checks/observability/chapObs004MemoryStoreExposed.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-OBS-004 — persistent memory/state store exposed', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-obs004-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('fires when the memory dir is group/other-readable', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'memory_dir: ./memory\n');
    mkdirSync(path.join(dir, 'memory'), { mode: 0o755 });

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapObs004MemoryStoreExposed.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-OBS-004');
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.message).toContain('readable by group or other');
    expect(findings[0]?.message).not.toContain('git repository');
  });

  it('fires when the memory dir is git-tracked and not gitignored', () => {
    mkdirSync(path.join(dir, '.git'));
    writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n');
    writeFileSync(path.join(dir, 'config.yaml'), 'memory_dir: ./memory\n');
    mkdirSync(path.join(dir, 'memory'), { mode: 0o700 });

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapObs004MemoryStoreExposed.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('git repository');
    expect(findings[0]?.message).not.toContain('readable by group or other');
  });

  it('stays silent when the memory dir is owner-only and covered by .gitignore', () => {
    mkdirSync(path.join(dir, '.git'));
    writeFileSync(path.join(dir, '.gitignore'), 'memory/\n');
    writeFileSync(path.join(dir, 'config.yaml'), 'memory_dir: ./memory\n');
    mkdirSync(path.join(dir, 'memory'), { mode: 0o700 });

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapObs004MemoryStoreExposed.run(model)).toEqual([]);
  });

  it('stays silent when memory_dir is configured but the directory does not exist on disk', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'memory_dir: ./memory\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapObs004MemoryStoreExposed.run(model)).toEqual([]);
  });

  it('stays silent when memory_dir is not configured at all', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  provider: anthropic\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapObs004MemoryStoreExposed.run(model)).toEqual([]);
  });
});
