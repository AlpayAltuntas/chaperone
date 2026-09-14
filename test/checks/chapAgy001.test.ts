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

    expect(findings).toHaveLength(2);
    for (const finding of findings) {
      expect(finding.checkId).toBe('CHAP-AGY-001');
      expect(finding.severity).toBe('critical');
      expect(finding.category).toBe('agency');
    }
    const skillNames = findings.map((f) => f.location.detail).sort();
    expect(skillNames).toEqual(['command-relay', 'shell-runner']);
  });

  it('stays silent on the clean fixture (no shell-capable skills)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapAgy001UnrestrictedShell.run(model)).toEqual([]);
  });

  it('returns no findings when there are no skills', () => {
    const { model } = discoverAgent({ targetPath: '/nonexistent/chaperone-target-xyz' });

    expect(chapAgy001UnrestrictedShell.run(model)).toEqual([]);
  });
});
