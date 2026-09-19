import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chapSec007EnvVarNotSet } from '../../src/checks/secrets/chapSec007EnvVarNotSet.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe("CHAP-SEC-007 — config references an environment variable that isn't set", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sec007-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    vi.unstubAllEnvs();
  });

  it('fires when the referenced variable is not set in the process environment', () => {
    vi.stubEnv('CHAP_SEC_007_TEST_VAR', undefined);
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  api_key: ${CHAP_SEC_007_TEST_VAR}\n');

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSec007EnvVarNotSet.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-SEC-007');
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.message).toContain('CHAP_SEC_007_TEST_VAR');
    // The advisory caveat must be in the message itself, not just docs.
    expect(findings[0]?.message).toContain('advisory');
  });

  it('fires when the referenced variable is set but empty', () => {
    vi.stubEnv('CHAP_SEC_007_TEST_VAR', '');
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  api_key: ${CHAP_SEC_007_TEST_VAR}\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec007EnvVarNotSet.run(model)).toHaveLength(1);
  });

  it('stays silent when the referenced variable is set and non-empty', () => {
    vi.stubEnv('CHAP_SEC_007_TEST_VAR', 'a-real-value');
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  api_key: ${CHAP_SEC_007_TEST_VAR}\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec007EnvVarNotSet.run(model)).toEqual([]);
  });

  it('stays silent for a reference with a fallback/default, regardless of env state', () => {
    vi.stubEnv('CHAP_SEC_007_TEST_VAR', undefined);
    writeFileSync(
      path.join(dir, 'config.yaml'),
      'llm:\n  api_key: ${CHAP_SEC_007_TEST_VAR:-default}\n',
    );

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec007EnvVarNotSet.run(model)).toEqual([]);
  });

  it('stays silent for a literal secret (not an env reference at all)', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  api_key: sk-ant-literal-dummy\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec007EnvVarNotSet.run(model)).toEqual([]);
  });

  it('stays silent when there is no config at all', () => {
    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSec007EnvVarNotSet.run(model)).toEqual([]);
  });
});
