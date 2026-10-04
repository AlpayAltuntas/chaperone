import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapSup002NoIntegrityVerification } from '../../src/checks/supplyChain/chapSup002NoIntegrityVerification.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SUP-002 — no integrity verification for skill dependencies', () => {
  it('fires only on skills that declare dependencies and have no lockfile in the vulnerable fixture', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapSup002NoIntegrityVerification.run(model);

    const skillNames = findings.map((f) => f.location.detail).sort();
    expect(skillNames).toEqual(['plugin-loader']);
    for (const finding of findings) {
      expect(finding.checkId).toBe('CHAP-SUP-002');
      expect(finding.severity).toBe('medium');
    }
  });

  it('stays silent on the clean fixture (every skill ships a lockfile)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapSup002NoIntegrityVerification.run(model)).toEqual([]);
  });

  // PROPOSED_FIXES.md 2.5 — a package.json with no `dependencies` has
  // nothing to install, so a missing lockfile verifies nothing either way.
  it('stays silent for a skill whose package.json declares no dependencies', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });
    const noDeps = model.skills.filter((skill) => skill.dependencies.names.length === 0);
    expect(noDeps.length).toBeGreaterThan(0);
    for (const skill of noDeps) {
      expect(skill.dependencies.manifestPath).not.toBeNull();
      expect(skill.dependencies.lockfilePath).toBeNull();
    }

    const flagged = new Set(
      chapSup002NoIntegrityVerification.run(model).map((f) => f.location.detail),
    );
    for (const skill of noDeps) {
      expect(flagged.has(skill.name)).toBe(false);
    }
  });
});
