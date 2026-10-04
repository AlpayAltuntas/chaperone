import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapAgy007PreapprovedShell } from '../../src/checks/agency/chapAgy007PreapprovedShell.js';
import { chapSup008AutoApprovedMcpServers } from '../../src/checks/supplyChain/chapSup008AutoApprovedMcpServers.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { parsePackageLock, parsePnpmLock, parseYarnLock } from '../../src/discovery/lockfiles.js';
import { chapSec001Fixer } from '../../src/fix/chapSec001Fixer.js';
import { gitignoreAction } from '../../src/fix/gitignore.js';
import type { AgentModel, ClaudeCodeSettingsFile } from '../../src/model/types.js';
import { formatAdvisoryLabel, formatProfileLabel } from '../../src/reporters/scoreLabel.js';
import type { ScanMetadata } from '../../src/reporters/types.js';

const META: ScanMetadata = {
  target: '/t',
  targetRootResolved: true,
  timestamp: 't',
  toolVersion: '0',
  inspected: [],
  skipped: [],
};

describe('report header labels', () => {
  it.each([
    [{}, null],
    [{ profile: 'default' }, null],
    [{ profile: 'default', profileDetected: true }, 'default (detected)'],
    [{ profile: 'mcp' }, 'mcp'],
  ])('profile %j -> %s', (extra, expected) => {
    expect(formatProfileLabel({ ...META, ...extra })).toBe(expected);
  });

  it('describes bundled and extra advisory data', () => {
    expect(formatAdvisoryLabel(META)).toBeNull();
    const data = {
      snapshotDate: '2026-10-04T00:00:00Z',
      bundledAdvisories: 600,
      extraFile: null,
      extraAdvisories: 0,
    };
    expect(formatAdvisoryLabel({ ...META, advisoryData: data })).toBe(
      'OSV snapshot 2026-10-04 (600 advisories)',
    );
    expect(
      formatAdvisoryLabel({
        ...META,
        advisoryData: { ...data, extraFile: 'osv.json', extraAdvisories: 5 },
      }),
    ).toBe('OSV snapshot 2026-10-04 (600 advisories) + 5 from osv.json');
  });
});

function withSettings(
  files: Array<{ scope: ClaudeCodeSettingsFile['scope']; data: unknown }>,
): AgentModel {
  const { model } = discoverAgent({ targetPath: 'test/fixtures/clean-agent' });
  return {
    ...model,
    claudeCodeSettings: files.map((f, i) => ({
      path: `/s${String(i)}.json`,
      scope: f.scope,
      data: f.data as ClaudeCodeSettingsFile['data'],
      secretFields: [],
      keyLines: {},
    })),
  };
}

describe('Claude Code rule and scope variants', () => {
  it.each([
    ['Bash(:*)', 'critical'],
    ['Bash( * )', 'critical'],
    ['Bash(rm -rf build)', 'high'],
    ['PowerShell(Invoke-Expression *)', 'high'],
    ['Bash(git status)', null],
    ['Read(./src/**)', null],
  ])('%s -> %s', (rule, severity) => {
    const findings = chapAgy007PreapprovedShell.run(
      withSettings([{ scope: 'project', data: { permissions: { allow: [rule, 42] } } }]),
    );
    expect(findings[0]?.severity ?? null).toBe(severity);
  });

  it('words CHAP-SUP-008 by scope', () => {
    const findings = chapSup008AutoApprovedMcpServers.run(
      withSettings([
        { scope: 'user', data: { enableAllProjectMcpServers: true } },
        { scope: 'local', data: { enableAllProjectMcpServers: true } },
        { scope: 'project', data: { enableAllProjectMcpServers: false } },
      ]),
    );
    expect(findings.map((f) => f.message.slice(0, 14))).toEqual([
      'User settings ',
      'Local settings',
    ]);
  });
});

describe('fix helpers outside a git repository', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-nogit-'));
    writeFileSync(
      path.join(dir, 'config.yaml'),
      'llm:\n  api_key: sk-ant-api03-EXAMPLEabcdefghijklmnopqrstuvwxyz\n  token: 12345678901\n',
    );
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("skips .gitignore and the rotate note, and quotes nothing it needn't", () => {
    const { model } = discoverAgent({ targetPath: dir });
    expect(gitignoreAction(model, path.join(dir, '.env'), false)).toBeNull();
    const plan = chapSec001Fixer.plan(model, { writeEnv: true });
    expect(plan?.notes.some((n) => n.includes('rotate'))).toBe(false);
    expect(plan?.actions.map((a) => a.kind)).toEqual(['write-file', 'append-lines']);
  });
});

describe('lockfile parser edge entries', () => {
  it('ignores non-semver versions and entries without names or versions', () => {
    expect(
      parsePackageLock(
        JSON.stringify({
          packages: {
            'node_modules/a': { version: 'file:../a' },
            'node_modules/b': { name: 'real-b', version: '1.0.0' },
            'node_modules/c': 'x',
          },
        }),
      ),
    ).toEqual([{ name: 'real-b', version: '1.0.0' }]);
    expect(parsePackageLock('[]')).toEqual([]);
    expect(parseYarnLock('noat:\n  version "1.0.0"\n"x@1":\n  resolved "y"\n')).toEqual([]);
    expect(parsePnpmLock('packages:\n  weird: {}\n')).toEqual([]);
    expect(parsePnpmLock('lockfileVersion: 9\n')).toEqual([]);
  });
});
