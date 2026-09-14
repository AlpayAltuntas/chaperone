import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapSup004DangerousInstallPatterns } from '../../src/checks/supplyChain/chapSup004DangerousInstallPatterns.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SUP-004 — dangerous install pattern', () => {
  it("fires on shell-runner's postinstall script and install.sh in the vulnerable fixture", () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapSup004DangerousInstallPatterns.run(model);

    expect(findings).toHaveLength(2);
    for (const finding of findings) {
      expect(finding.checkId).toBe('CHAP-SUP-004');
      expect(finding.location.detail).toBe('shell-runner');
    }
  });

  it('stays silent on the clean fixture (no dangerous install patterns)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapSup004DangerousInstallPatterns.run(model)).toEqual([]);
  });
});
