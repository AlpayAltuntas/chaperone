import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../../src/cli.js';
import { ScanReportSchema, type ScanReport } from '../../src/reporters/schema.js';

// improvement_plan.md 3.5 (--baseline). As with the other cli.*.test.ts
// files: only paths that don't call commander's command.error()/
// process.exit() are exercised in-process. A missing/invalid --baseline
// file goes through that same hard-error path and was verified manually
// instead (see DECISIONS.md, Phase 15): `chaperone scan --baseline
// nope.json` exits 1 with "baseline file not found: nope.json".
describe('cli scan — --baseline (in-process, non-throwing paths only)', () => {
  let logSpy: MockInstance<typeof console.log>;
  let dir: string;
  let originalExitCode: typeof process.exitCode;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-cli-baseline-test-'));
    originalExitCode = process.exitCode;
    process.exitCode = undefined;
  });

  afterEach(() => {
    logSpy.mockRestore();
    rmSync(dir, { recursive: true, force: true });
    process.exitCode = originalExitCode;
  });

  function scanJson(target: string, extraArgs: string[] = []): ScanReport {
    run(['node', 'chaperone', 'scan', target, '--format', 'json', ...extraArgs]);
    const printed = logSpy.mock.calls[0]?.[0] as string;
    logSpy.mockClear();
    return ScanReportSchema.parse(JSON.parse(printed));
  }

  it('reports nothing when the current scan exactly matches the baseline', () => {
    const target = path.join('test', 'fixtures', 'clean-agent');
    const current = scanJson(target);
    const baselinePath = path.join(dir, 'baseline.json');
    writeFileSync(baselinePath, JSON.stringify(current));

    const withBaseline = scanJson(target, ['--baseline', baselinePath]);

    expect(withBaseline.findings).toEqual([]);
  });

  it('reports only findings new since the baseline, and feeds --fail-on', () => {
    const target = path.join('test', 'fixtures', 'vulnerable-agent');
    const full = scanJson(target);
    const netFinding = full.findings.find((f) => f.checkId === 'CHAP-NET-001');
    if (netFinding === undefined) {
      throw new Error('expected CHAP-NET-001 in the vulnerable-agent fixture scan');
    }

    // Baseline is "everything except CHAP-NET-001" — simulating that
    // finding not having existed yet when the baseline was captured.
    const baselineReport: ScanReport = {
      ...full,
      findings: full.findings.filter((f) => f.checkId !== 'CHAP-NET-001'),
    };
    const baselinePath = path.join(dir, 'baseline.json');
    writeFileSync(baselinePath, JSON.stringify(baselineReport));
    // The capture scan above already set process.exitCode from its own
    // (unfiltered) findings — reset so the assertion below reflects only
    // the --baseline run.
    process.exitCode = undefined;

    // clean-agent-style low threshold isn't needed here — pick a
    // threshold only CHAP-NET-001 (critical) would trip if it were the
    // *only* finding left after the baseline diff.
    const withBaseline = scanJson(target, ['--baseline', baselinePath, '--fail-on', 'critical']);

    expect(withBaseline.findings).toHaveLength(1);
    expect(withBaseline.findings[0]?.checkId).toBe('CHAP-NET-001');
    expect(process.exitCode).toBe(1);
  });

  it('does not fail the build when every current finding is already in the baseline, even above --fail-on', () => {
    const target = path.join('test', 'fixtures', 'vulnerable-agent');
    const current = scanJson(target);
    const baselinePath = path.join(dir, 'baseline.json');
    writeFileSync(baselinePath, JSON.stringify(current));
    // The capture scan above (with real critical findings) already set
    // process.exitCode — reset it so only the --baseline run below is
    // under test, same as beforeEach does between tests.
    process.exitCode = undefined;

    scanJson(target, ['--baseline', baselinePath, '--fail-on', 'critical']);

    expect(process.exitCode).toBeUndefined();
  });

  it('accepts a report saved via --output as a baseline file', () => {
    const target = path.join('test', 'fixtures', 'clean-agent');
    const outFile = path.join(dir, 'saved-report.json');
    run(['node', 'chaperone', 'scan', target, '--format', 'json', '--output', outFile]);
    const saved = JSON.parse(readFileSync(outFile, 'utf8')) as ScanReport;
    expect(saved.findings.length).toBeGreaterThan(0);

    const withBaseline = scanJson(target, ['--baseline', outFile]);

    expect(withBaseline.findings).toEqual([]);
  });
});
