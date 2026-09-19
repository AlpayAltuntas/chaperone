import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../src/cli.js';

const SAMPLE_PLUGIN_PATH = path.join('test', 'fixtures', 'plugins', 'samplePlugin.cjs');

// improvement_plan.md 3.13 (Phase 21, --plugin). As with the other
// cli.*.test.ts files: only paths that don't call commander's
// command.error()/process.exit() are exercised in-process here. An
// invalid plugin module, a nonexistent plugin path, and a plugin
// check-ID collision with a built-in check all go through that same
// hard-error path and were verified manually instead — see
// DECISIONS.md, Phase 21 (loadPlugin/mergeChecks's own error paths are
// covered directly, without the CLI/command.error() layer, in
// test/engine/pluginLoader.test.ts).
describe('cli scan — --plugin (in-process, non-throwing paths only)', () => {
  let logSpy: MockInstance<typeof console.log>;
  let errorSpy: MockInstance<typeof console.error>;
  let dir: string;
  let originalExitCode: typeof process.exitCode;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-cli-plugin-test-'));
    mkdirSync(path.join(dir, 'skills', 'my-experimental-skill'), { recursive: true });
    writeFileSync(
      path.join(dir, 'skills', 'my-experimental-skill', 'package.json'),
      JSON.stringify({ name: 'my-experimental-skill', version: '1.0.0' }),
    );
    originalExitCode = process.exitCode;
    process.exitCode = undefined;
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    rmSync(dir, { recursive: true, force: true });
    process.exitCode = originalExitCode;
  });

  it('--plugin loads a real external check module and runs it against the scanned install', () => {
    run([
      'node',
      'chaperone',
      'scan',
      dir,
      '--plugin',
      SAMPLE_PLUGIN_PATH,
      '--only',
      'CHAP-CUSTOM-001',
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ checkId: string; message: string }> };
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.checkId).toBe('CHAP-CUSTOM-001');
    expect(report.findings[0]?.message).toContain('my-experimental-skill');
  });

  it('prints an explicit trust-boundary warning to stderr when a plugin is loaded', () => {
    run(['node', 'chaperone', 'scan', dir, '--plugin', SAMPLE_PLUGIN_PATH, '--format', 'json']);

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('no sandboxing'));
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining(SAMPLE_PLUGIN_PATH));
  });

  it('a plugin check feeds --fail-on like any built-in check', () => {
    run([
      'node',
      'chaperone',
      'scan',
      dir,
      '--plugin',
      SAMPLE_PLUGIN_PATH,
      '--fail-on',
      'medium',
      '--format',
      'json',
    ]);

    expect(process.exitCode).toBe(1);
  });

  it('prints no plugin warning at all when --plugin is not used', () => {
    run(['node', 'chaperone', 'scan', dir, '--format', 'json']);

    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('--plugin is repeatable — multiple flags all load', () => {
    const dir2 = mkdtempSync(path.join(os.tmpdir(), 'chaperone-cli-plugin-test2-'));
    try {
      writeFileSync(
        path.join(dir2, 'other-plugin.cjs'),
        `module.exports = { id: 'CHAP-CUSTOM-OTHER', title: 'other', severity: 'low', category: 'secrets', owasp: 'x', detects: 'x', heuristic: 'x', remediation: 'x', run: () => [] };`,
      );

      run([
        'node',
        'chaperone',
        'scan',
        dir,
        '--plugin',
        SAMPLE_PLUGIN_PATH,
        '--plugin',
        path.join(dir2, 'other-plugin.cjs'),
        '--only',
        'CHAP-CUSTOM-001,CHAP-CUSTOM-OTHER',
        '--format',
        'json',
      ]);

      const printed = logSpy.mock.calls[0]?.[0] as string;
      const report = JSON.parse(printed) as { findings: Array<{ checkId: string }> };
      expect(report.findings.some((f) => f.checkId === 'CHAP-CUSTOM-001')).toBe(true);
    } finally {
      rmSync(dir2, { recursive: true, force: true });
    }
  });

  it('a .chaperonerc.json plugins array loads a plugin without --plugin', () => {
    const rcPath = path.join(dir, '.chaperonerc.json');
    writeFileSync(rcPath, JSON.stringify({ plugins: [path.resolve(SAMPLE_PLUGIN_PATH)] }));

    run([
      'node',
      'chaperone',
      'scan',
      dir,
      '--config',
      rcPath,
      '--only',
      'CHAP-CUSTOM-001',
      '--format',
      'json',
    ]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ checkId: string }> };
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.checkId).toBe('CHAP-CUSTOM-001');
  });
});
