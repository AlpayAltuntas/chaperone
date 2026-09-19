import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapSup003KnownVulnerableDependencies } from '../../src/checks/supplyChain/chapSup003KnownVulnerableDependencies.js';
import { discoverAgent } from '../../src/discovery/index.js';

// Phase 18 (improvement_plan.md 1.15, real-fix half): this check now
// matches each skill's declared dependency version against a small,
// bundled, offline vulnerability snapshot (shared/vulnDb.ts) instead of
// firing on any manifest at all. Severity is back to `high` — a real
// version match, not "go run npm audit yourself".
describe('CHAP-SUP-003 — known-vulnerable dependency', () => {
  it('fires on plugin-loader (vulnerable fixture), which depends on a known-vulnerable lodash version', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapSup003KnownVulnerableDependencies.run(model);

    expect(findings).toHaveLength(1);
    const finding = findings[0];
    expect(finding?.checkId).toBe('CHAP-SUP-003');
    expect(finding?.severity).toBe('high');
    expect(finding?.location.detail).toBe('lodash@^4.17.15');
    expect(finding?.message).toContain('plugin-loader');
    expect(finding?.message).toContain('lodash@^4.17.15');
    expect(finding?.message).toContain('GHSA-p6mc-m468-83gw');
  });

  it('stays silent on the clean fixture — weather declares a patched lodash version', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapSup003KnownVulnerableDependencies.run(model)).toEqual([]);
  });

  it('stays silent for a skill with no dependency manifest at all', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sup003-test-'));
    try {
      const skillDir = path.join(dir, 'skills', 'no-manifest');
      mkdirSync(skillDir, { recursive: true });
      writeFileSync(path.join(skillDir, 'index.js'), 'module.exports = {};\n');

      const { model } = discoverAgent({ targetPath: dir });

      expect(chapSup003KnownVulnerableDependencies.run(model)).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('stays silent for a package not tracked in the offline snapshot, regardless of version', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sup003-test-'));
    try {
      const skillDir = path.join(dir, 'skills', 'unrelated-dep');
      mkdirSync(skillDir, { recursive: true });
      writeFileSync(
        path.join(skillDir, 'package.json'),
        JSON.stringify({ name: 'unrelated-dep', dependencies: { 'some-untracked-pkg': '0.0.1' } }),
      );

      const { model } = discoverAgent({ targetPath: dir });

      expect(chapSup003KnownVulnerableDependencies.run(model)).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('stays silent when the specifier has no parseable X.Y.Z version (e.g. "latest", a git URL)', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sup003-test-'));
    try {
      const skillDir = path.join(dir, 'skills', 'unparseable-version');
      mkdirSync(skillDir, { recursive: true });
      writeFileSync(
        path.join(skillDir, 'package.json'),
        JSON.stringify({
          name: 'unparseable-version',
          dependencies: { lodash: 'latest', minimist: 'github:user/minimist' },
        }),
      );

      const { model } = discoverAgent({ targetPath: dir });

      expect(chapSup003KnownVulnerableDependencies.run(model)).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fires on minimist below its fixed version, at critical severity', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sup003-test-'));
    try {
      const skillDir = path.join(dir, 'skills', 'minimist-user');
      mkdirSync(skillDir, { recursive: true });
      writeFileSync(
        path.join(skillDir, 'package.json'),
        JSON.stringify({ name: 'minimist-user', dependencies: { minimist: '1.2.5' } }),
      );

      const { model } = discoverAgent({ targetPath: dir });
      const findings = chapSup003KnownVulnerableDependencies.run(model);

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('critical');
      expect(findings[0]?.message).toContain('GHSA-xvch-5gv4-984h');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('does not flag a version exactly at the fixed boundary (the range is exclusive of "fixed")', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sup003-test-'));
    try {
      const skillDir = path.join(dir, 'skills', 'exactly-fixed');
      mkdirSync(skillDir, { recursive: true });
      writeFileSync(
        path.join(skillDir, 'package.json'),
        JSON.stringify({ name: 'exactly-fixed', dependencies: { minimist: '1.2.6' } }),
      );

      const { model } = discoverAgent({ targetPath: dir });

      expect(chapSup003KnownVulnerableDependencies.run(model)).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
