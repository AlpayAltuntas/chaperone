import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapSec001PlaintextSecrets } from '../../src/checks/secrets/chapSec001PlaintextSecrets.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SEC-001 — plaintext secrets in config', () => {
  it('fires on literal secrets in the vulnerable fixture', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapSec001PlaintextSecrets.run(model);

    expect(findings).toHaveLength(2);
    for (const finding of findings) {
      expect(finding.checkId).toBe('CHAP-SEC-001');
      expect(finding.severity).toBe('high');
      expect(finding.category).toBe('secrets');
      expect(finding.location.filePath).toBe(model.config.path);
    }
    const keyPaths = findings.map((f) => f.location.detail).sort();
    expect(keyPaths).toEqual(['channels.telegram.bot_token', 'llm.api_key']);

    // The real secret value must never appear in a finding.
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain('EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz');
  });

  it('stays silent on the clean fixture (env-reference secrets only)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapSec001PlaintextSecrets.run(model)).toEqual([]);
  });

  it('returns no findings when there is no config to inspect', () => {
    const { model } = discoverAgent({ targetPath: '/nonexistent/chaperone-target-xyz' });

    expect(chapSec001PlaintextSecrets.run(model)).toEqual([]);
  });
});
