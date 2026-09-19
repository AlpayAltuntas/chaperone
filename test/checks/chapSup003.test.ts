import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapSup003KnownVulnerableDependencies } from '../../src/checks/supplyChain/chapSup003KnownVulnerableDependencies.js';
import { discoverAgent } from '../../src/discovery/index.js';

// Per instruction.md §7, this check's v1 heuristic is deliberately weak: no
// live advisory API call is allowed (§14), so it just surfaces every
// dependency manifest it finds and points the user at `npm audit`. That
// means it fires on ANY skill with a package.json — vulnerable or
// hardened alike. There is no true-negative fixture case here by design;
// the negative case tested below is "no manifest at all", not "hardened
// manifest".
describe('CHAP-SUP-003 — dependency manifest not checked for known vulnerabilities', () => {
  it('fires on every skill with a manifest in the vulnerable fixture', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapSup003KnownVulnerableDependencies.run(model);

    const skillNames = findings.map((f) => f.location.detail).sort();
    expect(skillNames).toEqual(['command-relay', 'file-writer', 'shell-runner', 'web-fetcher']);
    // Regression test for improvement_plan.md 1.15 (mitigation half): this
    // signal is too weak to trip --fail-on high or meaningfully move the
    // posture score on its own.
    expect(findings.every((f) => f.severity === 'info')).toBe(true);
  });

  it('also fires on every skill with a manifest in the clean fixture (documented v1 limitation)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    const findings = chapSup003KnownVulnerableDependencies.run(model);

    const skillNames = findings.map((f) => f.location.detail).sort();
    expect(skillNames).toEqual(['messenger', 'notes', 'weather']);
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
});
