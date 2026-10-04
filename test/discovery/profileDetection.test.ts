import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../../src/cli.js';
import { detectProfile } from '../../src/discovery/profileDetection.js';

// PROPOSED_FIXES.md 6.3.
describe('detectProfile', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-detect-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const write = (relative: string, content = '{}'): void => {
    mkdirSync(path.dirname(path.join(dir, relative)), { recursive: true });
    writeFileSync(path.join(dir, relative), content);
  };

  it.each([
    ['config.yaml', 'default'],
    ['.mcp.json', 'mcp'],
    [path.join('.vscode', 'mcp.json'), 'mcp'],
    [path.join('.claude', 'settings.json'), 'claude-code'],
  ])('detects %s as %s', (file, profile) => {
    write(file);
    expect(detectProfile(dir)).toEqual({ profile, detected: true });
  });

  it('prefers claude-code over mcp, since it also reads .mcp.json', () => {
    write('.mcp.json');
    write(path.join('.claude', 'settings.local.json'));
    expect(detectProfile(dir)).toEqual({ profile: 'claude-code', detected: true });
  });

  it('errors when the default format and another profile both match', () => {
    write('config.yaml');
    write('.mcp.json');
    const result = detectProfile(dir);
    expect(result).toMatchObject({ candidates: ['default', 'mcp'] });
    expect('error' in result && result.error).toContain('Pass --profile');
  });

  it('falls back to default, undetected, when nothing matches', () => {
    expect(detectProfile(dir)).toEqual({ profile: 'default', detected: false });
  });

  it('classifies a file path by name', () => {
    write('.claude.json');
    write(path.join('.claude', 'settings.json'));
    expect(detectProfile(path.join(dir, '.claude.json'))).toEqual({
      profile: 'mcp',
      detected: true,
    });
    expect(detectProfile(path.join(dir, '.claude', 'settings.json'))).toEqual({
      profile: 'claude-code',
      detected: true,
    });
  });
});

describe('cli scan — profile auto-detection', () => {
  let dir: string;
  let logSpy: MockInstance<typeof console.log>;
  let originalExitCode: typeof process.exitCode;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-detect-cli-'));
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    originalExitCode = process.exitCode;
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    logSpy.mockRestore();
    process.exitCode = originalExitCode;
  });

  it('scans an MCP project without --profile and says the profile was detected', () => {
    writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({ mcpServers: { sh: { command: 'bash', args: ['-c', 'echo hi'] } } }),
      { mode: 0o600 },
    );

    run(['node', 'chaperone', 'scan', dir, '--format', 'json']);

    const report = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as {
      profile: { name: string; detected: boolean };
      findings: Array<{ checkId: string }>;
    };
    expect(report.profile).toEqual({ name: 'mcp', detected: true });
    expect(report.findings.map((f) => f.checkId)).toContain('CHAP-AGY-001');

    logSpy.mockClear();
    run(['node', 'chaperone', 'scan', dir, '--no-color']);
    expect(logSpy.mock.calls[0]?.[0] as string).toContain('Profile: mcp (detected)');
  });
});
