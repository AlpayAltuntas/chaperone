import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../src/cli.js';

// improvement_plan.md 3.1 (Phase 17, --profile). As with the other
// cli.*.test.ts files: only paths that don't call commander's
// command.error()/process.exit() are exercised in-process. An invalid
// --profile value goes through that same hard-error path and was
// verified manually instead: `chaperone scan --profile bogus` exits 1
// with "must be one of: default, mcp".
describe('cli scan — --profile (in-process, non-throwing paths only)', () => {
  let logSpy: MockInstance<typeof console.log>;
  let originalEnv: string | undefined;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    originalEnv = process.env['CHAPERONE_PROFILE'];
  });

  afterEach(() => {
    logSpy.mockRestore();
    if (originalEnv === undefined) {
      delete process.env['CHAPERONE_PROFILE'];
    } else {
      process.env['CHAPERONE_PROFILE'] = originalEnv;
    }
  });

  it('--profile mcp scans a real MCP server config instead of the fictional config.yaml format', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'mcp-vulnerable'),
      '--profile',
      'mcp',
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ checkId: string }> };
    expect(report.findings.some((f) => f.checkId === 'CHAP-SEC-001')).toBe(true);
    expect(report.findings.some((f) => f.checkId === 'CHAP-SUP-001')).toBe(true);
  });

  it('defaults to the fictional profile when --profile is omitted', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'clean-agent'),
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { target: string };
    expect(report.target).toContain('clean-agent');
  });

  it('CHAPERONE_PROFILE env var selects the profile when --profile is not passed', () => {
    process.env['CHAPERONE_PROFILE'] = 'mcp';

    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'mcp-clean'),
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ checkId: string }> };
    expect(report.findings.some((f) => f.checkId === 'CHAP-SEC-001')).toBe(false);
  });
});
