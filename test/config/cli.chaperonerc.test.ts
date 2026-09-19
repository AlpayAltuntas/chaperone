import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../../src/cli.js';
import { DEFAULT_CONFIG_FILENAME } from '../../src/config/chaperoneConfig.js';

// improvement_plan.md 3.4 (.chaperonerc.json). As with cli.exitcode.test.ts
// and cli.options.test.ts: only paths that don't call commander's
// command.error()/process.exit() are exercised in-process. An unknown
// check ID inside disabledChecks goes through the same hard-error path as
// an unknown --skip ID and was verified manually instead (see
// DECISIONS.md, Phase 14): `chaperone scan --config <file>` with
// `{"disabledChecks":["CHAP-FAKE-999"]}` exits 1 with "Unknown check ID:
// CHAP-FAKE-999. Run `chaperone checks` to see available check IDs."
describe('cli scan — .chaperonerc.json (in-process, non-throwing paths only)', () => {
  let logSpy: MockInstance<typeof console.log>;
  let errorSpy: MockInstance<typeof console.error>;
  let dir: string;
  let originalExitCode: typeof process.exitCode;
  let originalEnv: string | undefined;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-cli-rc-test-'));
    originalExitCode = process.exitCode;
    process.exitCode = undefined;
    originalEnv = process.env['CHAPERONE_CONFIG'];
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    rmSync(dir, { recursive: true, force: true });
    process.exitCode = originalExitCode;
    if (originalEnv === undefined) {
      delete process.env['CHAPERONE_CONFIG'];
    } else {
      process.env['CHAPERONE_CONFIG'] = originalEnv;
    }
  });

  function readJsonReport(): {
    findings: Array<{ checkId: string; severity: string }>;
    summary: { score: number };
  } {
    const printed = logSpy.mock.calls[0]?.[0] as string;
    return JSON.parse(printed) as {
      findings: Array<{ checkId: string; severity: string }>;
      summary: { score: number };
    };
  }

  it('--config applies severityOverrides, which also changes --fail-on (not just display)', () => {
    const configPath = path.join(dir, 'rc.json');
    writeFileSync(
      configPath,
      JSON.stringify({ severityOverrides: { 'CHAP-SEC-003': 'critical' } }),
    );

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--config',
      configPath,
      '--format',
      'json',
    ]);

    const report = readJsonReport();
    const overridden = report.findings.find((f) => f.checkId === 'CHAP-SEC-003');
    expect(overridden?.severity).toBe('critical');
    // clean-agent normally never reaches the default --fail-on (high)
    // threshold; this proves the override feeds the fail-on decision.
    expect(process.exitCode).toBe(1);
  });

  it('--config ignore entry removes a finding entirely', () => {
    const configPath = path.join(dir, 'rc.json');
    writeFileSync(
      configPath,
      JSON.stringify({ ignore: [{ checkId: 'CHAP-SEC-003', reason: 'accepted risk' }] }),
    );

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--config',
      configPath,
      '--format',
      'json',
    ]);

    const report = readJsonReport();
    expect(report.findings.some((f) => f.checkId === 'CHAP-SEC-003')).toBe(false);
  });

  it('an expired ignore entry does not suppress the finding, and prints a warning instead', () => {
    const configPath = path.join(dir, 'rc.json');
    writeFileSync(
      configPath,
      JSON.stringify({
        ignore: [{ checkId: 'CHAP-SEC-003', reason: 'temp', expires: '2020-01-01' }],
      }),
    );

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--config',
      configPath,
      '--format',
      'json',
    ]);

    const report = readJsonReport();
    expect(report.findings.some((f) => f.checkId === 'CHAP-SEC-003')).toBe(true);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('expired on 2020-01-01'));
  });

  it('--config disabledChecks prevents the check from running at all', () => {
    const configPath = path.join(dir, 'rc.json');
    writeFileSync(configPath, JSON.stringify({ disabledChecks: ['CHAP-SEC-003'] }));

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--config',
      configPath,
      '--format',
      'json',
    ]);

    const report = readJsonReport();
    expect(report.findings.some((f) => f.checkId === 'CHAP-SEC-003')).toBe(false);
  });

  it('--config scoreWeights changes the computed posture score', () => {
    const configPath = path.join(dir, 'rc.json');
    writeFileSync(configPath, JSON.stringify({ scoreWeights: { medium: 20 } }));

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--format',
      'json',
    ]);
    const baseline = readJsonReport();
    logSpy.mockClear();

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--config',
      configPath,
      '--format',
      'json',
    ]);
    const withWeights = readJsonReport();

    expect(withWeights.summary.score).toBeLessThan(baseline.summary.score);
  });

  it('--config scoreWeights changes the score in console and markdown output too', () => {
    const configPath = path.join(dir, 'rc.json');
    writeFileSync(configPath, JSON.stringify({ scoreWeights: { medium: 20 } }));

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--config',
      configPath,
      '--no-color',
    ]);
    const consolePrinted = logSpy.mock.calls[0]?.[0] as string;
    expect(consolePrinted).toContain('51/100');
    logSpy.mockClear();

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--config',
      configPath,
      '--format',
      'markdown',
    ]);
    const markdownPrinted = logSpy.mock.calls[0]?.[0] as string;
    expect(markdownPrinted).toContain('51/100');
  });

  it('CHAPERONE_CONFIG env var is used when --config is not passed', () => {
    const configPath = path.join(dir, 'rc.json');
    writeFileSync(configPath, JSON.stringify({ ignore: [{ checkId: 'CHAP-SEC-003' }] }));
    process.env['CHAPERONE_CONFIG'] = configPath;

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--format',
      'json',
    ]);

    const report = readJsonReport();
    expect(report.findings.some((f) => f.checkId === 'CHAP-SEC-003')).toBe(false);
  });

  it('auto-discovers ./.chaperonerc.json from the current directory when --config is not passed', () => {
    writeFileSync(
      path.join(dir, DEFAULT_CONFIG_FILENAME),
      JSON.stringify({ ignore: [{ checkId: 'CHAP-SEC-003' }] }),
    );
    const fixtureAbs = path.resolve('test', 'fixtures', 'clean-agent');
    const originalCwd = process.cwd();
    process.chdir(dir);
    try {
      run(['node', 'chaperone', 'scan', fixtureAbs, '--format', 'json']);
    } finally {
      process.chdir(originalCwd);
    }

    const report = readJsonReport();
    expect(report.findings.some((f) => f.checkId === 'CHAP-SEC-003')).toBe(false);
  });
});
