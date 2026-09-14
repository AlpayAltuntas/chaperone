import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapAgy001UnrestrictedShell } from '../../src/checks/agency/chapAgy001UnrestrictedShell.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-AGY-001 — unrestricted shell execution', () => {
  it('fires on the shell-runner skill in the vulnerable fixture', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapAgy001UnrestrictedShell.run(model);

    expect(findings).toHaveLength(1);
    const [finding] = findings;
    expect(finding?.checkId).toBe('CHAP-AGY-001');
    expect(finding?.severity).toBe('critical');
    expect(finding?.category).toBe('agency');
    expect(finding?.location.detail).toBe('shell-runner');
    expect(finding?.location.filePath).toContain('shell-runner');
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
