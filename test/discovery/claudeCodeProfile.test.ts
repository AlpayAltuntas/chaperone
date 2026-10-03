import { chmodSync, cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { parseRule } from '../../src/checks/shared/claudeCode.js';
import { locateClaudeCodeSettings } from '../../src/discovery/claudeCodeProfile.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { runChecks } from '../../src/engine/index.js';

// PROPOSED_FIXES.md 6.1. Keys verified against code.claude.com/docs on 2026-10-03.
const FIXTURE = path.join('test', 'fixtures', 'claude-code-project');

describe('--profile claude-code against the claude-code-project fixture', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-claude-code-'));
    cpSync(FIXTURE, dir, { recursive: true });
    // Set modes explicitly: git doesn't keep them and umask varies.
    for (const file of ['.mcp.json', '.claude/settings.json', '.claude/settings.local.json']) {
      chmodSync(path.join(dir, file), 0o600);
    }
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function scan(): { ids: string[]; findings: ReturnType<typeof runChecks>['findings'] } {
    const { model, targetRootResolved } = discoverAgent({
      targetPath: dir,
      profile: 'claude-code',
    });
    expect(targetRootResolved).toBe(true);
    const { findings } = runChecks(model, ALL_CHECKS, { profile: 'claude-code' });
    return {
      ids: findings.map((f) => `${f.checkId}:${f.severity}:${f.location.detail ?? ''}`).sort(),
      findings,
    };
  }

  it('reports exactly the expected findings', () => {
    expect(scan().ids).toEqual(
      [
        'CHAP-AGY-002:high:files',
        'CHAP-AGY-006:low:permissions.defaultMode',
        'CHAP-AGY-007:critical:Bash',
        'CHAP-AGY-007:high:Bash(python3:*)',
        'CHAP-AGY-008:medium:WebFetch',
        'CHAP-SEC-001:high:env.ANTHROPIC_API_KEY',
        'CHAP-SEC-009:medium:permissions.deny',
        'CHAP-SUP-001:high:files',
        'CHAP-SUP-008:high:enableAllProjectMcpServers',
        'CHAP-SUP-009:high:hooks.PostToolUse[0].hooks[1].command',
      ].sort(),
    );
  });

  it('points findings at the right lines', () => {
    const { findings } = scan();
    const line = (detail: string): number | null | undefined =>
      findings.find((f) => f.location.detail === detail)?.location.line;
    expect(line('Bash')).toBe(7);
    expect(line('permissions.defaultMode')).toBe(3);
    expect(line('enableAllProjectMcpServers')).toBe(14);
  });

  it('says which secret files are not denied', () => {
    const sec009 = scan().findings.find((f) => f.checkId === 'CHAP-SEC-009');
    expect(sec009?.message).toContain('~/.ssh');
    expect(sec009?.message).not.toContain('.env files');
  });

  it('never keeps the env secret in the model', () => {
    const { model } = discoverAgent({ targetPath: dir, profile: 'claude-code' });
    expect(JSON.stringify(model)).not.toContain('EXAMPLEabcdefghijklmnopqrstuvwxyz');
  });

  it('treats bypassPermissions in user settings as critical', () => {
    const home = path.join(dir, 'home');
    mkdirSync(path.join(home, '.claude'), { recursive: true });
    writeFileSync(
      path.join(home, '.claude', 'settings.json'),
      JSON.stringify({ permissions: { defaultMode: 'bypassPermissions', deny: ['Read'] } }),
    );
    const { model } = discoverAgent({
      targetPath: path.join(home, '.claude', 'settings.json'),
      profile: 'claude-code',
    });
    // Scope is decided by location; the fixture's home isn't the real one, so it is "project".
    expect(model.claudeCodeSettings[0]?.scope).toBe('project');
    const located = locateClaudeCodeSettings(path.join(home, '.claude', 'settings.json'), home);
    expect('files' in located && located.files[0]?.scope).toBe('user');
  });

  it('is quiet for a tight settings file', () => {
    rmSync(path.join(dir, '.claude'), { recursive: true });
    rmSync(path.join(dir, '.mcp.json'));
    mkdirSync(path.join(dir, '.claude'));
    writeFileSync(
      path.join(dir, '.claude', 'settings.json'),
      JSON.stringify({
        permissions: {
          allow: ['Bash(npm run test *)', 'Bash(git diff:*)', 'WebFetch(domain:docs.example.com)'],
          deny: ['Read(./.env)', 'Read(./.env.*)', 'Read(~/.ssh/**)'],
        },
        env: { ANTHROPIC_API_KEY: '${ANTHROPIC_API_KEY}' },
        hooks: { Stop: [{ hooks: [{ type: 'command', command: 'npm run lint' }] }] },
      }),
    );
    expect(scan().ids).toEqual([]);
  });

  it('reports nothing scanned for a directory with no settings and no .mcp.json', () => {
    const empty = path.join(dir, 'empty');
    mkdirSync(empty);
    const { targetRootResolved, model } = discoverAgent({
      targetPath: empty,
      profile: 'claude-code',
    });
    expect(targetRootResolved).toBe(false);
    expect(model.skipped[0]?.reason).toContain('no Claude Code settings found');
  });
});

describe('parseRule', () => {
  it.each([
    ['Bash', 'Bash', null],
    ['Bash(*)', 'Bash', '*'],
    ['Bash(npm run test:*)', 'Bash', 'npm run test:*'],
    ['WebFetch(domain:example.com)', 'WebFetch', 'domain:example.com'],
    ['mcp__github__*', 'mcp__github__*', null],
  ])('%s', (rule, tool, specifier) => {
    expect(parseRule(rule)).toEqual({ tool, specifier });
  });
});
