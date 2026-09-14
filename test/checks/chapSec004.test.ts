import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSec004SecretsReachLogs } from '../../src/checks/secrets/chapSec004SecretsReachLogs.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SEC-004 — secrets likely to reach logs', () => {
  it('fires on the vulnerable fixture (debug level while literal secrets are configured)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapSec004SecretsReachLogs.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-SEC-004');
    expect(findings[0]?.message).toContain('debug');
  });

  // The clean-agent fixture is NOT used for the negative case here: its log
  // file's checked-out permission bits are not deterministic across
  // machines/CI (same caveat as CHAP-SEC-003), and this check has a
  // permission-based OR-branch. Both branches get isolated, deterministic
  // temp-dir coverage below instead.
  describe('isolated temp installs (deterministic permissions)', () => {
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sec004-test-'));
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it('stays silent with a safe log level, no literal secrets, and a locked-down log file', () => {
      writeFileSync(
        path.join(dir, 'config.yaml'),
        'llm:\n  api_key: ${ANTHROPIC_API_KEY}\nlogging:\n  level: info\n  path: ./agent.log\n',
      );
      writeFileSync(path.join(dir, 'agent.log'), 'log line\n', { mode: 0o600 });

      const { model } = discoverAgent({ targetPath: dir });

      expect(chapSec004SecretsReachLogs.run(model)).toEqual([]);
    });

    it('fires when the log file alone is group/other-readable, even with a safe level and no secrets', () => {
      writeFileSync(
        path.join(dir, 'config.yaml'),
        'llm:\n  api_key: ${ANTHROPIC_API_KEY}\nlogging:\n  level: info\n  path: ./agent.log\n',
      );
      writeFileSync(path.join(dir, 'agent.log'), 'log line\n', { mode: 0o644 });

      const { model } = discoverAgent({ targetPath: dir });

      const findings = chapSec004SecretsReachLogs.run(model);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.message).toContain('readable by group or other');
    });

    it('stays silent when logging is not configured at all', () => {
      writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  provider: anthropic\n');

      const { model } = discoverAgent({ targetPath: dir });

      expect(chapSec004SecretsReachLogs.run(model)).toEqual([]);
    });
  });
});
