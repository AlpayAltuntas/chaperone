import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSec001PlaintextSecrets } from '../../src/checks/secrets/chapSec001PlaintextSecrets.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SEC-001 — plaintext secrets in config', () => {
  it('fires on literal secrets in the vulnerable fixture, with a real line number (improvement_plan.md 1.17)', () => {
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

    const apiKeyFinding = findings.find((f) => f.location.detail === 'llm.api_key');
    expect(apiKeyFinding?.location.line).toBe(6);

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

  // improvement_plan.md 1.17's own definition of done: JSON configs stay
  // null, documented rather than silently inconsistent with YAML.
  describe('JSON config (no line numbers — documented limitation)', () => {
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sec001-json-test-'));
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it('still fires, but with a null line number', () => {
      writeFileSync(
        path.join(dir, 'config.json'),
        JSON.stringify({ llm: { api_key: 'sk-ant-literal-dummy-value' } }),
      );

      const { model } = discoverAgent({ targetPath: dir });
      const findings = chapSec001PlaintextSecrets.run(model);

      expect(findings).toHaveLength(1);
      expect(findings[0]?.location.line).toBeNull();
    });
  });
});
