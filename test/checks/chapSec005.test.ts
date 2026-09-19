import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSec005SecretsInExistingLogs } from '../../src/checks/secrets/chapSec005SecretsInExistingLogs.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SEC-005 — secret already present in existing log content', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sec005-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('fires when a secret-shaped value is already present in the log file', () => {
    writeFileSync(
      path.join(dir, 'config.yaml'),
      'llm:\n  api_key: ${ANTHROPIC_API_KEY}\nlogging:\n  path: ./agent.log\n',
    );
    writeFileSync(
      path.join(dir, 'agent.log'),
      '2026-01-01T00:00:00Z DEBUG {"api_key": "sk-real-looking-dummy-leaked"}\n',
    );

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSec005SecretsInExistingLogs.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-SEC-005');
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.message).toContain('api_key');
    expect(findings[0]?.message).not.toContain('sk-real-looking-dummy-leaked');
  });

  it('stays silent when the log file holds no secret-shaped content', () => {
    writeFileSync(
      path.join(dir, 'config.yaml'),
      'llm:\n  api_key: ${ANTHROPIC_API_KEY}\nlogging:\n  path: ./agent.log\n',
    );
    writeFileSync(path.join(dir, 'agent.log'), 'request_id=8f14e45fceea167a status=ok\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec005SecretsInExistingLogs.run(model)).toEqual([]);
  });

  it('stays silent when there is no log file at all', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  provider: anthropic\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec005SecretsInExistingLogs.run(model)).toEqual([]);
  });
});
