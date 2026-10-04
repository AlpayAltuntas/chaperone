import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../../src/cli.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { applyFixPlan, FIXERS } from '../../src/fix/index.js';
import { setConfigValues } from '../../src/fix/configEdit.js';

// PROPOSED_FIXES.md 5.
const mode = (p: string): number => statSync(p).mode & 0o777;

describe('setConfigValues', () => {
  it('edits JSON in place, preserving key order and formatting', () => {
    const source =
      '{\n    "b": 1,\n    "gateway": { "host": "0.0.0.0",   "port": 8080 },\n    "a": "x"\n}\n';
    expect(setConfigValues(source, 'json', [{ keyPath: 'gateway.host', value: '127.0.0.1' }])).toBe(
      '{\n    "b": 1,\n    "gateway": { "host": "127.0.0.1",   "port": 8080 },\n    "a": "x"\n}\n',
    );
  });

  it('keeps YAML comments', () => {
    const out = setConfigValues('# top\ntrust:\n  auto_execute_links: true # risky\n', 'yaml', [
      { keyPath: 'trust.auto_execute_links', value: false },
    ]);
    expect(out).toContain('# top');
    expect(out).toContain('auto_execute_links: false');
  });

  it('refuses a JSON path it cannot locate', () => {
    expect(() => setConfigValues('{}', 'json', [{ keyPath: 'a.b', value: 'x' }])).toThrow(
      /cannot locate/,
    );
  });
});

describe.skipIf(process.platform === 'win32')('fixers against a real install', () => {
  let dir: string;
  const fixer = (id: string) => {
    const found = FIXERS.find((f) => f.checkId === id);
    if (found === undefined) {
      throw new Error(id);
    }
    return found;
  };

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-fixers-'));
    mkdirSync(path.join(dir, '.git'));
    writeFileSync(path.join(dir, '.gitignore'), 'node_modules/');
    writeFileSync(
      path.join(dir, 'config.json'),
      JSON.stringify(
        {
          llm: { apiKey: 'sk-ant-api03-EXAMPLEabcdefghijklmnopqrstuvwxyz' },
          gateway: { host: '0.0.0.0', auth: { token: '${GW}' } },
          trust: { autoExecuteLinks: true },
          memory_dir: './memory',
        },
        null,
        2,
      ),
      { mode: 0o644 },
    );
    mkdirSync(path.join(dir, 'memory'), { mode: 0o755 });
    chmodSync(path.join(dir, 'memory'), 0o755);
    mkdirSync(path.join(dir, 'skills'));
    chmodSync(path.join(dir, 'skills'), 0o777);
    writeFileSync(path.join(dir, '.env.production'), 'API_TOKEN=dummy-literal-value-123\n', {
      mode: 0o644,
    });
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function applyAll(id: string, options = {}): void {
    const { model } = discoverAgent({ targetPath: dir });
    const plan = fixer(id).plan(model, options);
    expect(plan).not.toBeNull();
    if (plan !== null) {
      applyFixPlan(plan);
    }
  }

  it('CHAP-SEC-001 with --write-env moves the secret to a 0600 .env and gitignores it', () => {
    applyAll('CHAP-SEC-001', { writeEnv: true });
    const config = readFileSync(path.join(dir, 'config.json'), 'utf8');
    expect(config).toContain('"apiKey": "${LLM_APIKEY}"');
    expect(config).not.toContain('EXAMPLEabcdef');
    const env = readFileSync(path.join(dir, '.env'), 'utf8');
    expect(env).toBe('LLM_APIKEY=sk-ant-api03-EXAMPLEabcdefghijklmnopqrstuvwxyz\n');
    expect(mode(path.join(dir, '.env'))).toBe(0o600);
    expect(readFileSync(path.join(dir, '.gitignore'), 'utf8')).toBe('node_modules/\n/.env\n');
  });

  it('never prints the secret in the plan, even with --write-env', () => {
    const { model } = discoverAgent({ targetPath: dir });
    const plan = fixer('CHAP-SEC-001').plan(model, { writeEnv: true });
    expect(JSON.stringify({ changes: plan?.changes, notes: plan?.notes })).not.toContain(
      'EXAMPLEabcdef',
    );
    expect(plan?.notes.join(' ')).toContain('rotate');
  });

  it('CHAP-SEC-002 gitignores the config', () => {
    applyAll('CHAP-SEC-002');
    expect(readFileSync(path.join(dir, '.gitignore'), 'utf8')).toContain('/config.json');
  });

  it('CHAP-SEC-003 restricts the config to the owner', () => {
    applyAll('CHAP-SEC-003');
    expect(mode(path.join(dir, 'config.json'))).toBe(0o600);
  });

  it('CHAP-SEC-006 gitignores and restricts a sidecar file', () => {
    applyAll('CHAP-SEC-006');
    expect(mode(path.join(dir, '.env.production'))).toBe(0o600);
    expect(readFileSync(path.join(dir, '.gitignore'), 'utf8')).toContain('/.env.production');
  });

  it('CHAP-SEC-008 removes group/other write only', () => {
    applyAll('CHAP-SEC-008');
    expect(mode(path.join(dir, 'skills'))).toBe(0o755);
  });

  it('CHAP-OBS-004 restricts and gitignores the memory dir', () => {
    applyAll('CHAP-OBS-004');
    expect(mode(path.join(dir, 'memory'))).toBe(0o700);
    expect(readFileSync(path.join(dir, '.gitignore'), 'utf8')).toContain('/memory/');
  });

  it('CHAP-NET-001 and CHAP-INJ-004 edit the camelCase JSON config in place', () => {
    applyAll('CHAP-NET-001');
    applyAll('CHAP-INJ-004');
    const config = JSON.parse(readFileSync(path.join(dir, 'config.json'), 'utf8')) as {
      gateway: { host: string };
      trust: { autoExecuteLinks: boolean };
    };
    expect(config.gateway.host).toBe('127.0.0.1');
    expect(config.trust.autoExecuteLinks).toBe(false);
  });

  it('applying twice is harmless (append-lines skips existing lines)', () => {
    applyAll('CHAP-SEC-002');
    const { model } = discoverAgent({ targetPath: dir });
    expect(fixer('CHAP-SEC-002').plan(model)).toBeNull();
  });

  describe('chaperone fix --all', () => {
    let logSpy: MockInstance<typeof console.log>;
    let originalExitCode: typeof process.exitCode;

    beforeEach(() => {
      logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
      originalExitCode = process.exitCode;
    });

    afterEach(() => {
      logSpy.mockRestore();
      process.exitCode = originalExitCode;
    });

    it('previews every fix without writing, then applies them with --dry-run --write', () => {
      run(['node', 'chaperone', 'fix', '--all', dir, '--dry-run']);
      const preview = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
      for (const id of [
        'CHAP-SEC-001',
        'CHAP-SEC-003',
        'CHAP-SEC-008',
        'CHAP-NET-001',
        'CHAP-INJ-004',
        'CHAP-OBS-004',
      ]) {
        expect(preview).toContain(`Proposed fix for ${id}`);
      }
      expect(preview).not.toContain('EXAMPLEabcdef');
      expect(mode(path.join(dir, 'config.json'))).toBe(0o644);

      logSpy.mockClear();
      run(['node', 'chaperone', 'fix', '--all', dir, '--dry-run', '--write']);
      expect(mode(path.join(dir, 'config.json'))).toBe(0o600);
      expect(mode(path.join(dir, 'skills'))).toBe(0o755);
    });
  });
});
