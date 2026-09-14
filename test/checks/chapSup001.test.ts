import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapSup001UnverifiedSources } from '../../src/checks/supplyChain/chapSup001UnverifiedSources.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SUP-001 — skill from an unverified source', () => {
  it('fires on every unpinned skill in the vulnerable fixture', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapSup001UnverifiedSources.run(model);

    const skillNames = findings.map((f) => f.location.detail).sort();
    expect(skillNames).toEqual(['command-relay', 'file-writer', 'shell-runner', 'web-fetcher']);
    for (const finding of findings) {
      expect(finding.checkId).toBe('CHAP-SUP-001');
      expect(finding.severity).toBe('high');
    }
  });

  it('stays silent on the clean fixture (every skill is pinned to a semver version)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapSup001UnverifiedSources.run(model)).toEqual([]);
  });
});
