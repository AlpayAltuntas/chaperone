import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../src/cli.js';
import { ScanReportSchema, type ScanReport } from '../src/reporters/schema.js';

// improvement_plan.md 3.2 (Phase 20, --all). As with the other
// cli.*.test.ts files: only paths that don't call commander's
// command.error()/process.exit() are exercised in-process. --all
// matching zero directories goes through that same hard-error path and
// was verified manually instead (see DECISIONS.md, Phase 20).
describe('cli scan — --all (multi-root batch scanning, in-process, non-throwing paths only)', () => {
  let logSpy: MockInstance<typeof console.log>;
  let dir: string;
  let originalExitCode: typeof process.exitCode;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-cli-all-test-'));
    cpSync(path.join('test', 'fixtures', 'clean-agent'), path.join(dir, 'clean-bot'), {
      recursive: true,
    });
    cpSync(path.join('test', 'fixtures', 'vulnerable-agent'), path.join(dir, 'vulnerable-bot'), {
      recursive: true,
    });
    originalExitCode = process.exitCode;
    process.exitCode = undefined;
  });

  afterEach(() => {
    logSpy.mockRestore();
    rmSync(dir, { recursive: true, force: true });
    process.exitCode = originalExitCode;
  });

  it('--all <dir>/* scans every immediate subdirectory and aggregates a JSON array', () => {
    run(['node', 'chaperone', 'scan', '--all', `${dir}/*`, '--format', 'json']);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const parsed = JSON.parse(printed) as unknown[];
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(2);
    for (const entry of parsed) {
      expect(() => ScanReportSchema.parse(entry)).not.toThrow();
    }
    const targets = (parsed as ScanReport[]).map((r) => r.target).sort();
    expect(targets).toEqual([path.join(dir, 'clean-bot'), path.join(dir, 'vulnerable-bot')].sort());
  });

  it('fails the build (exit 1) when any one target trips --fail-on, even if others are clean', () => {
    run(['node', 'chaperone', 'scan', '--all', `${dir}/*`, '--format', 'json']);

    expect(process.exitCode).toBe(1);
  });

  it('aggregates a non-JSON format as header-separated sections, one per target', () => {
    run(['node', 'chaperone', 'scan', '--all', `${dir}/*`, '--no-color', '--summary-only']);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('===== Target 1/2:');
    expect(printed).toContain('===== Target 2/2:');
    expect(printed).toContain('clean-bot');
    expect(printed).toContain('vulnerable-bot');
  });

  it('merges a --format sarif run into one multi-run document, not two concatenated ones', () => {
    run(['node', 'chaperone', 'scan', '--all', `${dir}/*`, '--format', 'sarif']);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const sarif = JSON.parse(printed) as { version: string; runs: unknown[] };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(2);
  });

  it('a pattern with no trailing /* degenerates to an ordinary single-target scan', () => {
    run(['node', 'chaperone', 'scan', '--all', path.join(dir, 'clean-bot'), '--format', 'json']);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const parsed: unknown = JSON.parse(printed);
    expect(Array.isArray(parsed)).toBe(false);
    expect((parsed as ScanReport).target).toBe(path.join(dir, 'clean-bot'));
  });

  it('writes one combined file with --output, not N separate files', () => {
    const outFile = path.join(dir, 'combined.json');

    run([
      'node',
      'chaperone',
      'scan',
      '--all',
      `${dir}/*`,
      '--format',
      'json',
      '--output',
      outFile,
    ]);

    const content = readFileSync(outFile, 'utf8');
    const parsed = JSON.parse(content) as unknown[];
    expect(parsed).toHaveLength(2);
  });
});
