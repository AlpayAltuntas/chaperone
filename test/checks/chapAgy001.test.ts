import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapAgy001UnrestrictedShell } from '../../src/checks/agency/chapAgy001UnrestrictedShell.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-AGY-001 — unrestricted shell execution', () => {
  it('fires on every shell-capable skill in the vulnerable fixture', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapAgy001UnrestrictedShell.run(model);

    expect(findings).toHaveLength(3);
    for (const finding of findings) {
      expect(finding.checkId).toBe('CHAP-AGY-001');
      expect(finding.severity).toBe('critical');
      expect(finding.category).toBe('agency');
    }
    // py-cache-cleaner (Phase 16, Python: subprocess.run, regex-detected)
    // joins the two existing JS/TS shell-capable skills.
    const skillNames = findings.map((f) => f.location.detail).sort();
    expect(skillNames).toEqual(['command-relay', 'py-cache-cleaner', 'shell-runner']);
  });

  it('stays silent on the clean fixture (no shell-capable skills)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapAgy001UnrestrictedShell.run(model)).toEqual([]);
  });

  it('returns no findings when there are no skills', () => {
    const { model } = discoverAgent({ targetPath: '/nonexistent/chaperone-target-xyz' });

    expect(chapAgy001UnrestrictedShell.run(model)).toEqual([]);
  });

  // PROPOSED_FIXES.md 2.9 — a declared confirmation gate is a real (if
  // self-declared) mitigation: still reported, but downgraded from
  // critical, and the message no longer claims no gate was found.
  it('downgrades to high when the skill declares a confirmation gate', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });
    const gatedModel = {
      ...model,
      skills: model.skills.map((skill) =>
        skill.name === 'shell-runner' ? { ...skill, confirmationRequired: true } : skill,
      ),
    };

    const findings = chapAgy001UnrestrictedShell.run(gatedModel);

    const gated = findings.find((f) => f.location.detail === 'shell-runner');
    expect(gated?.severity).toBe('high');
    expect(gated?.message).toMatch(/declares a confirmation gate/);
    expect(gated?.message).not.toMatch(/no detected command allowlist or confirmation gate/);

    const ungated = findings.filter((f) => f.location.detail !== 'shell-runner');
    expect(ungated).toHaveLength(2);
    for (const finding of ungated) {
      expect(finding.severity).toBe('critical');
    }
  });

  it('treats confirmationRequired: false the same as no declaration (critical)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });
    const explicitFalse = {
      ...model,
      skills: model.skills.map((skill) => ({ ...skill, confirmationRequired: false })),
    };

    for (const finding of chapAgy001UnrestrictedShell.run(explicitFalse)) {
      expect(finding.severity).toBe('critical');
    }
  });
});
