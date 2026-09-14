import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../src/cli.js';

// Only the non-throwing paths are exercised in-process here. An invalid
// --format/--fail-on value goes through commander's default error handler,
// which calls process.exit() directly — running that in-process would kill
// the vitest worker mid-suite. That path was verified manually instead (see
// DECISIONS.md, Phase 4): `node dist/cli.js scan ... --format xml` exits 1
// with a clear "must be one of: ..." message.
describe('cli scan — exit codes and output (in-process, non-throwing paths only)', () => {
  let logSpy: MockInstance<typeof console.log>;
  let originalExitCode: typeof process.exitCode;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    originalExitCode = process.exitCode;
    process.exitCode = undefined;
  });

  afterEach(() => {
    logSpy.mockRestore();
    process.exitCode = originalExitCode;
  });

  it('exits non-zero by default (--fail-on high) when the vulnerable fixture has high+ findings', () => {
    run(['node', 'chaperone', 'scan', path.join('test', 'fixtures', 'vulnerable-agent')]);

    expect(process.exitCode).toBe(1);
  });

  it('exits zero when raising the threshold above every finding severity present', () => {
    // clean-agent's only findings are CHAP-SUP-003 (high); nothing reaches critical.
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--fail-on',
      'critical',
    ]);

    expect(process.exitCode).toBeUndefined();
  });

  it('prints JSON to stdout for --format json', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--format',
      'json',
    ]);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(() => {
      JSON.parse(printed);
    }).not.toThrow();
  });

  it('prints SARIF to stdout for --format sarif', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--format',
      'sarif',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const sarif = JSON.parse(printed) as { version: string };
    expect(sarif.version).toBe('2.1.0');
  });

  describe('--output', () => {
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-cli-output-test-'));
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it('writes the report to a file instead of stdout', () => {
      const outFile = path.join(dir, 'report.json');

      run([
        'node',
        'chaperone',
        'scan',
        path.join('test', 'fixtures', 'clean-agent'),
        '--format',
        'json',
        '--output',
        outFile,
      ]);

      expect(logSpy).not.toHaveBeenCalled();
      const content = readFileSync(outFile, 'utf8');
      expect(() => {
        JSON.parse(content);
      }).not.toThrow();
    });

    it('strips ANSI color codes from a console-format report written to a file', () => {
      const outFile = path.join(dir, 'report.txt');

      run([
        'node',
        'chaperone',
        'scan',
        path.join('test', 'fixtures', 'vulnerable-agent'),
        '--output',
        outFile,
      ]);

      const content = readFileSync(outFile, 'utf8');
      expect(content.includes('\u001b[')).toBe(false); // no ANSI escape sequences
      expect(content).toContain('CRITICAL');
    });
  });
});
