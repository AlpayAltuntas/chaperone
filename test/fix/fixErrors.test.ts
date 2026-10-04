import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../../src/cli.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { FIXERS } from '../../src/fix/index.js';

// The `fix` command's error paths call commander's command.error(), which
// exits the process; process.exit is stubbed to throw so they can run in-process.
describe('cli fix — error paths', () => {
  let exitSpy: MockInstance<typeof process.exit>;
  let errSpy: MockInstance<typeof process.stderr.write>;
  let logSpy: MockInstance<typeof console.log>;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`exit ${String(code)}`);
    });
    errSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errSpy.mockRestore();
    logSpy.mockRestore();
  });

  const stderr = (): string => errSpy.mock.calls.map((c) => String(c[0])).join('');

  it.each([
    [['fix'], 'Pass a check ID or --all'],
    [['fix', 'CHAP-NOPE-999'], "No fixer available for 'CHAP-NOPE-999'"],
    [['fix', 'CHAP-SEC-003', '.', '--write'], '--write requires --dry-run'],
    [
      ['fix', '--all', '/nonexistent/chaperone-fix-target'],
      'Could not locate an installation to fix',
    ],
  ])('%j', (args, message) => {
    const originalExitCode = process.exitCode;
    const consoleErr = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      run(['node', 'chaperone', ...args]);
    } catch {
      // commander may rethrow the stubbed exit outside the action's try/catch.
    } finally {
      consoleErr.mockRestore();
      process.exitCode = originalExitCode;
    }
    expect(exitSpy).toHaveBeenCalled();
    expect(stderr()).toContain(message);
  });
});

describe('fixers propose nothing for a clean install', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-fix-clean-'));
    writeFileSync(
      path.join(dir, 'config.yaml'),
      'gateway:\n  host: 127.0.0.1\n  auth:\n    token: ${GW}\ntrust:\n  auto_execute_links: false\n',
      { mode: 0o600 },
    );
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it.each(FIXERS.map((f) => f.checkId))('%s', (checkId) => {
    const { model } = discoverAgent({ targetPath: dir });
    expect(FIXERS.find((f) => f.checkId === checkId)?.plan(model)).toBeNull();
  });

  it('reports nothing to fix through the CLI with --all', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      run(['node', 'chaperone', 'fix', '--all', dir]);
      expect(String(logSpy.mock.calls[0]?.[0])).toContain(
        'Nothing to fix for any check with a fixer',
      );
    } finally {
      logSpy.mockRestore();
    }
  });
});
