import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../src/cli.js';

// improvement_plan.md 3.14 (Phase 22, `chaperone fix`). As with the
// other cli.*.test.ts files: only paths that don't call commander's
// command.error()/process.exit() are exercised in-process. --write
// without --dry-run, an unknown check ID, and an unresolved target all
// go through that hard-error path and were verified manually instead —
// see DECISIONS.md, Phase 22 (both manual verification and the
// underlying logic are also covered directly, without the CLI/
// command.error() layer, in test/fix/chapSec001Fixer.test.ts).
describe('cli fix — guided remediation (in-process, non-throwing paths only)', () => {
  let logSpy: MockInstance<typeof console.log>;
  let dir: string;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-cli-fix-test-'));
    writeFileSync(
      path.join(dir, 'config.yaml'),
      ['llm:', '  api_key: sk-ant-real-secret-value-shhh', ''].join('\n'),
    );
  });

  afterEach(() => {
    logSpy.mockRestore();
    rmSync(dir, { recursive: true, force: true });
  });

  it('dry-run (default, no flags) prints the proposed change and writes nothing', () => {
    const before = readFileSync(path.join(dir, 'config.yaml'), 'utf8');

    run(['node', 'chaperone', 'fix', 'CHAP-SEC-001', dir]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('Proposed fix for CHAP-SEC-001');
    expect(printed).toContain('${LLM_API_KEY}');
    expect(printed).not.toContain('sk-ant-real-secret-value-shhh');
    expect(readFileSync(path.join(dir, 'config.yaml'), 'utf8')).toBe(before);
  });

  it('--dry-run alone (no --write) also writes nothing', () => {
    const before = readFileSync(path.join(dir, 'config.yaml'), 'utf8');

    run(['node', 'chaperone', 'fix', 'CHAP-SEC-001', dir, '--dry-run']);

    expect(readFileSync(path.join(dir, 'config.yaml'), 'utf8')).toBe(before);
  });

  it('--dry-run --write together shows the change AND actually writes it', () => {
    run(['node', 'chaperone', 'fix', 'CHAP-SEC-001', dir, '--dry-run', '--write']);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('Proposed fix for CHAP-SEC-001');

    const content = readFileSync(path.join(dir, 'config.yaml'), 'utf8');
    expect(content).toContain('api_key: ${LLM_API_KEY}');
    expect(content).not.toContain('sk-ant-real-secret-value-shhh');
  });

  it('the change is shown before the write confirmation, in that order', () => {
    run(['node', 'chaperone', 'fix', 'CHAP-SEC-001', dir, '--dry-run', '--write']);

    const calls = logSpy.mock.calls.map((call) => call[0] as string);
    const diffIndex = calls.findIndex((c) => c.includes('Proposed fix'));
    const writeIndex = calls.findIndex((c) => c.includes('Wrote'));
    expect(diffIndex).toBeGreaterThanOrEqual(0);
    expect(writeIndex).toBeGreaterThan(diffIndex);
  });

  it('reports "nothing to fix" and writes nothing once the finding is already resolved', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  api_key: ${LLM_API_KEY}\n');
    const before = readFileSync(path.join(dir, 'config.yaml'), 'utf8');

    run(['node', 'chaperone', 'fix', 'CHAP-SEC-001', dir]);

    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('Nothing to fix');
    expect(readFileSync(path.join(dir, 'config.yaml'), 'utf8')).toBe(before);
  });
});

describe('cli scan — remains fully read-only regardless of chaperone fix existing', () => {
  let logSpy: MockInstance<typeof console.log>;
  let dir: string;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-cli-fix-readonly-test-'));
    writeFileSync(
      path.join(dir, 'config.yaml'),
      ['llm:', '  api_key: sk-ant-real-secret-value-shhh', ''].join('\n'),
    );
  });

  afterEach(() => {
    logSpy.mockRestore();
    rmSync(dir, { recursive: true, force: true });
  });

  it('chaperone scan never modifies the fixable config file, even with fixable findings present', () => {
    const before = readFileSync(path.join(dir, 'config.yaml'), 'utf8');
    const mtimeBefore = statSync(path.join(dir, 'config.yaml')).mtimeMs;

    run(['node', 'chaperone', 'scan', dir, '--format', 'json']);

    expect(readFileSync(path.join(dir, 'config.yaml'), 'utf8')).toBe(before);
    expect(statSync(path.join(dir, 'config.yaml')).mtimeMs).toBe(mtimeBefore);
  });
});
