import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../src/cli.js';

// Regression test for improvement_plan.md 1.12: an unexpected error deep
// in the scan pipeline (simulated here via a reporter that throws) must
// not be indistinguishable from "findings met --fail-on" — both used to
// exit 1. This is a dedicated file (rather than added to
// cli.exitcode.test.ts) because vi.mock's module replacement applies for
// the whole file and would otherwise affect every other CLI test that
// relies on the real reporters. vi.mock calls are hoisted above imports
// by vitest's transform, so this takes effect before `run` above is
// resolved even though it's written after the import.
// Phase 20 (improvement_plan.md 3.2/3.3): cli.ts's scan action now
// always calls renderMultiTargetReport (which degenerates to
// renderReport's own output for the single-target case that's still the
// overwhelming majority of invocations — see reporters/index.ts) rather
// than renderReport directly, so that's the export this simulated
// failure needs to target.
vi.mock('../src/reporters/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/reporters/index.js')>();
  return {
    ...actual,
    renderMultiTargetReport: vi.fn(() => {
      throw new Error('simulated reporter failure');
    }),
  };
});

describe('cli scan — unexpected tool errors get a distinct exit code', () => {
  let errorSpy: MockInstance<typeof console.error>;
  let logSpy: MockInstance<typeof console.log>;
  let originalExitCode: typeof process.exitCode;

  beforeEach(() => {
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    originalExitCode = process.exitCode;
    process.exitCode = undefined;
  });

  afterEach(() => {
    errorSpy.mockRestore();
    logSpy.mockRestore();
    process.exitCode = originalExitCode;
  });

  it('catches the error, prints a clean message, and exits 2 — not 1 (findings) or an uncaught crash', () => {
    expect(() => {
      run(['node', 'chaperone', 'scan', path.join('test', 'fixtures', 'clean-agent')]);
    }).not.toThrow();

    expect(process.exitCode).toBe(2);
    expect(logSpy).not.toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalledTimes(1);
    const printed = errorSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('unexpected error');
    expect(printed).toContain('simulated reporter failure');
  });
});
