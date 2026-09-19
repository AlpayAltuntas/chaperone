import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { ALL_CHECKS } from '../src/checks/index.js';
import { formatCheckExplanation, formatChecksList, run } from '../src/cli.js';
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

describe('formatCheckExplanation', () => {
  it('includes id, title, severity, category, owasp, detects, heuristic, and remediation', () => {
    const check = ALL_CHECKS.find((c) => c.id === 'CHAP-SEC-001');
    if (check === undefined) {
      throw new Error('CHAP-SEC-001 missing from ALL_CHECKS');
    }

    const output = formatCheckExplanation(check);

    expect(output).toContain('CHAP-SEC-001 — Plaintext secrets in config');
    expect(output).toContain('Severity: HIGH');
    expect(output).toContain('Category: secrets');
    expect(output).toContain(`OWASP:    ${check.owasp}`);
    expect(output).toContain(check.detects);
    expect(output).toContain(check.heuristic);
    expect(output).toContain(check.remediation);
  });

  it('uses severityNote instead of the plain severity when set', () => {
    const check = ALL_CHECKS.find((c) => c.id === 'CHAP-SUP-003');
    if (check === undefined) {
      throw new Error('CHAP-SUP-003 missing from ALL_CHECKS');
    }
    const { severityNote } = check;
    if (severityNote === undefined) {
      throw new Error('CHAP-SUP-003 is expected to have a severityNote');
    }

    const output = formatCheckExplanation(check);

    expect(output).toContain(`Severity: ${severityNote}`);
    expect(output).not.toContain('Severity: INFO');
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

  // improvement_plan.md 3.7. The unknown-check-id path goes through
  // command.error() -> process.exit(), same "verified manually instead"
  // caveat as cli.exitcode.test.ts documents for other command.error()
  // paths: `chaperone explain CHAP-FAKE-999` exits 1 with "Unknown check
  // ID: CHAP-FAKE-999. Run `chaperone checks` to see available check
  // IDs." (manually verified).
  it('explain prints full detail for a known check', () => {
    run(['node', 'chaperone', 'explain', 'CHAP-SEC-001']);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('CHAP-SEC-001 — Plaintext secrets in config');
    expect(printed).toContain('Severity: HIGH');
    expect(printed).toContain('Category: secrets');
    expect(printed).toContain('Detects:');
    expect(printed).toContain('Heuristic:');
    expect(printed).toContain('Remediation:');
  });

  it('explain shows the severityNote override instead of the plain severity, when set', () => {
    run(['node', 'chaperone', 'explain', 'CHAP-SUP-003']);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('Severity: Info (demoted from High)');
  });

  it('the version subcommand prints just the version (alongside -V/--version)', () => {
    run(['node', 'chaperone', 'version']);

    expect(logSpy).toHaveBeenCalledWith(VERSION);
  });
});

// improvement_plan.md 3.8: category/severity display filters, distinct
// from --fail-on (verified separately in cli.exitcode.test.ts, since that
// file already manages process.exitCode around each test).
describe('cli scan — --only-category/--skip-category/--min-severity (display filters)', () => {
  let logSpy: MockInstance<typeof console.log>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it('--only-category shows only findings in the listed categories', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--only-category',
      'secrets',
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ category: string }> };
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.every((f) => f.category === 'secrets')).toBe(true);
  });

  it('--only-category accepts a comma-separated list', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--only-category',
      'secrets,network',
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ category: string }> };
    const categories = new Set(report.findings.map((f) => f.category));
    expect(categories).toEqual(new Set(['secrets', 'network']));
  });

  it('--skip-category hides findings in the listed categories', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--skip-category',
      'secrets',
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ category: string }> };
    expect(report.findings.some((f) => f.category === 'secrets')).toBe(false);
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it('--min-severity hides findings below the given severity', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--min-severity',
      'critical',
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ severity: string }> };
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.every((f) => f.severity === 'critical')).toBe(true);
  });

  it('rejects an unrecognized category the same way an unrecognized severity is rejected', () => {
    expect(() => {
      run([
        'node',
        'chaperone',
        'scan',
        path.join('test', 'fixtures', 'vulnerable-agent'),
        '--only-category',
        'not-a-real-category',
      ]);
    }).toThrow();
  });
});

// improvement_plan.md 3.11: console-only presentation modes.
describe('cli scan — --quiet/--summary-only (console presentation modes)', () => {
  let logSpy: MockInstance<typeof console.log>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it('--quiet prints one compact line per finding, still includes the summary/score', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--no-color',
      '--quiet',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('[CHAP-SEC-001] HIGH');
    expect(printed).not.toContain('Plaintext secrets in config');
    expect(printed).not.toContain('Remediation:');
    expect(printed).toMatch(/posture score \d+\/100/);
  });

  it('--summary-only prints no per-finding detail at all', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--no-color',
      '--summary-only',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).not.toContain('CHAP-SEC-001');
    expect(printed).not.toContain('CRITICAL (');
    expect(printed).toMatch(/posture score \d+\/100/);
    expect(printed).toContain('Summary:');
  });

  // --quiet and --summary-only both being set goes through commander's
  // .conflicts() error path, which calls process.exit() directly — same
  // "verified manually instead" caveat as cli.exitcode.test.ts documents
  // for invalid --format/--fail-on values. Manually verified: `chaperone
  // scan ... --quiet --summary-only` exits 1 with "option '--quiet'
  // cannot be used with option '--summary-only'".
});

// improvement_plan.md 3.12: environment-variable support for common flags.
describe('cli scan — environment-variable flag support', () => {
  let logSpy: MockInstance<typeof console.log>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
    vi.unstubAllEnvs();
  });

  it('CHAPERONE_FORMAT sets the default format when --format is not passed', () => {
    vi.stubEnv('CHAPERONE_FORMAT', 'json');

    run(['node', 'chaperone', 'scan', path.join('test', 'fixtures', 'vulnerable-agent')]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(() => JSON.parse(printed) as unknown).not.toThrow();
  });

  it('an explicit --format flag overrides CHAPERONE_FORMAT', () => {
    vi.stubEnv('CHAPERONE_FORMAT', 'json');

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--format',
      'console',
      '--no-color',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('Chaperone scan report');
  });

  it('CHAPERONE_MIN_SEVERITY applies the same display filter as --min-severity', () => {
    vi.stubEnv('CHAPERONE_MIN_SEVERITY', 'critical');

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ severity: string }> };
    expect(report.findings.every((f) => f.severity === 'critical')).toBe(true);
  });
});
