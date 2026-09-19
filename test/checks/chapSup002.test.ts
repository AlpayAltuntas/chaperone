import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapSup002NoIntegrityVerification } from '../../src/checks/supplyChain/chapSup002NoIntegrityVerification.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SUP-002 — no integrity verification for skill dependencies', () => {
  it('fires on every skill missing a lockfile in the vulnerable fixture', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapSup002NoIntegrityVerification.run(model);

    const skillNames = findings.map((f) => f.location.detail).sort();
    expect(skillNames).toEqual([
      'command-relay',
      'file-writer',
      'plugin-loader',
      'py-cache-cleaner',
      'shell-runner',
      'web-fetcher',
    ]);
    for (const finding of findings) {
      expect(finding.checkId).toBe('CHAP-SUP-002');
      expect(finding.severity).toBe('medium');
    }
  });

  it('stays silent on the clean fixture (every skill ships a lockfile)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapSup002NoIntegrityVerification.run(model)).toEqual([]);
  });
});
