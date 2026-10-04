import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { isCiEnvironment, run } from '../src/cli.js';

// PROPOSED_FIXES.md 7.4.5.
describe('isCiEnvironment', () => {
  it.each([
    [undefined, false],
    ['', false],
    ['false', false],
    ['0', false],
    ['true', true],
    ['1', true],
  ])('CI=%s -> %s', (value, expected) => {
    expect(isCiEnvironment(value === undefined ? {} : { CI: value })).toBe(expected);
  });
});

describe('CHAP-SEC-007 in CI', () => {
  let logSpy: MockInstance<typeof console.log>;
  let originalExitCode: typeof process.exitCode;
  const target = path.join('test', 'fixtures', 'clean-agent');

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    originalExitCode = process.exitCode;
  });

  afterEach(() => {
    logSpy.mockRestore();
    vi.unstubAllEnvs();
    process.exitCode = originalExitCode;
  });

  const report = (): { findings: Array<{ checkId: string }>; skipped: Array<{ reason: string }> } =>
    JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string) as {
      findings: Array<{ checkId: string }>;
      skipped: Array<{ reason: string }>;
    };

  it('is skipped, and says so, when CI is set', () => {
    vi.stubEnv('CI', 'true');
    run(['node', 'chaperone', 'scan', target, '--format', 'json']);
    expect(report().findings.some((f) => f.checkId === 'CHAP-SEC-007')).toBe(false);
    expect(
      report().skipped.some((s) => s.reason.startsWith('CHAP-SEC-007 skipped: CI is set')),
    ).toBe(true);
  });

  it('still runs in CI when named with --only', () => {
    vi.stubEnv('CI', 'true');
    vi.stubEnv('ANTHROPIC_API_KEY', '');
    run(['node', 'chaperone', 'scan', target, '--format', 'json', '--only', 'CHAP-SEC-007']);
    expect(report().findings.some((f) => f.checkId === 'CHAP-SEC-007')).toBe(true);
  });
});
