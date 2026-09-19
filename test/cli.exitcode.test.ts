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
    // clean-agent's only findings are CHAP-SUP-003 (info); nothing reaches critical.
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

  // improvement_plan.md 3.8: --min-severity/--only-category/--skip-category
  // are display filters only — --fail-on must still evaluate every
  // finding that actually ran, not just the ones the display filter
  // chose to show.
  it('--min-severity filtering the display does not change the --fail-on decision', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      // Display only critical findings, but keep the default --fail-on
      // (high) — the vulnerable fixture has high-severity findings that
      // this display filter would hide, so if --fail-on were reading the
      // filtered set instead of the full one, this would wrongly pass.
      '--min-severity',
      'critical',
    ]);

    expect(process.exitCode).toBe(1);
  });

  it('--only-category filtering the display to a clean category does not suppress a real failure', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'vulnerable-agent'),
      // CHAP-NET-001 (critical) lives outside the "observability" category
      // — if --fail-on read the filtered display set, this run would
      // wrongly report success.
      '--only-category',
      'observability',
    ]);

    expect(process.exitCode).toBe(1);
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

  // improvement_plan.md 3.9 — tested against both fixtures, per the
  // phase's definition of done.
  describe.each(['vulnerable-agent', 'clean-agent'])(
    '--format markdown / --format gha against %s',
    (fixture) => {
      it('prints a Markdown table for --format markdown', () => {
        run([
          'node',
          'chaperone',
          'scan',
          path.join('test', 'fixtures', fixture),
          '--format',
          'markdown',
        ]);

        const printed = logSpy.mock.calls[0]?.[0] as string;
        expect(printed).toContain('# Chaperone scan report');
        expect(printed).toContain('**Summary:**');
      });

      it('prints GitHub Actions annotations for --format gha', () => {
        run([
          'node',
          'chaperone',
          'scan',
          path.join('test', 'fixtures', fixture),
          '--format',
          'gha',
        ]);

        const printed = logSpy.mock.calls[0]?.[0] as string;
        expect(printed).toMatch(/^::(error|warning|notice)/);
        expect(printed).toContain('::notice::Chaperone scan:');
      });

      // improvement_plan.md 3.10 (Phase 19) — self-contained HTML,
      // tested against both fixtures per the phase's own DoD.
      it('prints a complete, self-contained HTML document for --format html', () => {
        run([
          'node',
          'chaperone',
          'scan',
          path.join('test', 'fixtures', fixture),
          '--format',
          'html',
        ]);

        const printed = logSpy.mock.calls[0]?.[0] as string;
        expect(printed.startsWith('<!doctype html>')).toBe(true);
        expect(printed).toContain('</html>');
        expect(printed).toContain('Chaperone scan report');
        expect(printed).not.toContain('<script');
      });
    },
  );

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

    // improvement_plan.md 3.10 (Phase 19) DoD, literally: "opens
    // correctly as a static file". Writes a real .html file to disk
    // and reads it back, same as a user double-clicking it in a file
    // browser or opening it with `open`/`xdg-open` would.
    it('writes a complete, self-contained .html file that reads back as a valid static document', () => {
      const outFile = path.join(dir, 'report.html');

      run([
        'node',
        'chaperone',
        'scan',
        path.join('test', 'fixtures', 'vulnerable-agent'),
        '--format',
        'html',
        '--output',
        outFile,
      ]);

      const content = readFileSync(outFile, 'utf8');
      expect(content.startsWith('<!doctype html>')).toBe(true);
      expect(content.trimEnd().endsWith('</html>')).toBe(true);
      expect(content).not.toContain('<script');
      expect(content).not.toContain('<link');
    });
  });
});
