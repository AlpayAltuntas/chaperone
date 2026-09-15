import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { ALL_CHECKS } from '../src/checks/index.js';
import { formatChecksList, run } from '../src/cli.js';
import { VERSION } from '../src/version.js';

// As with cli.exitcode.test.ts: only paths that don't call commander's
// command.error()/process.exit() are exercised in-process. Unknown check
// IDs, --only/--skip leaving nothing to run, and --output write failures
// all go through that path and were verified manually instead (see
// DECISIONS.md, Phase 5) — running them here would kill the vitest worker.
describe('formatChecksList', () => {
  it('lists every check with its id, severity, and title', () => {
    const output = formatChecksList(ALL_CHECKS);

    expect(output).toContain(`Chaperone check catalog (${String(ALL_CHECKS.length)} checks)`);
    expect(output).toContain('CHAP-SEC-001');
    expect(output).toContain('HIGH');
    expect(output).toContain('Plaintext secrets in config');
  });

  it('lists one line per check', () => {
    const output = formatChecksList(ALL_CHECKS);
    const checkLines = output.split('\n').filter((line) => line.startsWith('CHAP-'));

    expect(checkLines).toHaveLength(ALL_CHECKS.length);
  });

  it('handles an empty registry without throwing', () => {
    expect(() => formatChecksList([])).not.toThrow();
    expect(formatChecksList([])).toContain('Chaperone check catalog (0 checks)');
  });
});

describe('cli scan — --only/--skip/--no-color (in-process, non-throwing paths only)', () => {
  let logSpy: MockInstance<typeof console.log>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it('--only runs just the listed check', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--only',
      'CHAP-NET-001',
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ checkId: string }> };
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.checkId).toBe('CHAP-NET-001');
  });

  it('--skip excludes the listed checks', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--skip',
      'CHAP-SEC-001,CHAP-SUP-003',
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ checkId: string }> };
    const checkIds = new Set(report.findings.map((f) => f.checkId));
    expect(checkIds.has('CHAP-SEC-001')).toBe(false);
    expect(checkIds.has('CHAP-SUP-003')).toBe(false);
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it('--only accepts a comma-separated list', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--only',
      'CHAP-NET-001,CHAP-SEC-001',
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ checkId: string }> };
    const checkIds = new Set(report.findings.map((f) => f.checkId));
    expect(checkIds).toEqual(new Set(['CHAP-NET-001', 'CHAP-SEC-001']));
  });

  it('does not run any checks when no installation could be located at all (no path, no default)', () => {
    // Unlike an explicit nonexistent path (which still "resolves" structurally
    // — see discoverAgent's graceful-degradation tests — and so still runs
    // checks against an empty model), omitting the path entirely with no
    // default install present is the one case where targetRootResolved is
    // false, and cli.ts skips running checks altogether for it.
    run(['node', 'chaperone', 'scan', '--format', 'json']);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: unknown[]; targetRootResolved: boolean };
    expect(report.targetRootResolved).toBe(false);
    expect(report.findings).toEqual([]);
  });

  it('--no-color strips ANSI codes even on a run that would otherwise use them', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--no-color',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed.includes('[')).toBe(false);
    expect(printed).toContain('CRITICAL');
  });

  it('prints the checks subcommand catalog', () => {
    run(['node', 'chaperone', 'checks']);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('Chaperone check catalog');
    expect(printed).toContain('CHAP-SEC-001');
  });

  it('the version subcommand prints just the version (alongside -V/--version)', () => {
    run(['node', 'chaperone', 'version']);

    expect(logSpy).toHaveBeenCalledWith(VERSION);
  });
});
