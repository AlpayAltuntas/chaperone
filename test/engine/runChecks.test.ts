import { describe, expect, it, vi } from 'vitest';
import { runChecks } from '../../src/engine/index.js';
import type { Check } from '../../src/engine/types.js';
import type { AgentModel, Finding } from '../../src/model/types.js';

const EMPTY_MODEL: AgentModel = {
  targetRoot: '/fake',
  config: { path: null, format: null, data: null, secretFields: [], keyLines: {} },
  sidecarSecretFiles: [],
  git: {
    hasAncestorGitDir: false,
    gitDirPath: null,
    gitRootPath: null,
    gitignoreFiles: [],
    configPathRelativeToGitRoot: null,
  },
  permissions: [],
  skills: [],
  gateway: {
    present: false,
    bindHost: null,
    port: null,
    authConfigured: null,
    authTokenIsDefaultOrEmpty: null,
    tlsEnabled: null,
  },
  logging: {
    present: false,
    level: null,
    path: null,
    redactSecrets: null,
    auditLogEnabled: null,
    existingSecretMatches: [],
  },
  memory: { present: false, dir: null },
  recoverability: { killSwitchDocumented: false },
  inspected: [],
  skipped: [],
};

function makeFinding(checkId: string): Finding {
  return {
    checkId,
    title: 'Test finding',
    severity: 'low',
    category: 'secrets',
    owasp: 'LLM06',
    message: 'test',
    location: { filePath: null, line: null, detail: null },
    remediation: 'test',
  };
}

function makeCheck(id: string, run: Check['run']): Check {
  return {
    id,
    title: id,
    severity: 'low',
    category: 'secrets',
    owasp: 'LLM06',
    detects: 'test',
    heuristic: 'test',
    remediation: 'test',
    run,
  };
}

describe('runChecks', () => {
  it('aggregates findings from every registered check', () => {
    const checks: Check[] = [
      makeCheck('A', () => [makeFinding('A')]),
      makeCheck('B', () => [makeFinding('B'), makeFinding('B')]),
    ];

    const result = runChecks(EMPTY_MODEL, checks);

    expect(result.findings).toHaveLength(3);
    expect(result.checksRun).toEqual(['A', 'B']);
    expect(result.checksSkipped).toEqual([]);
    expect(result.internalErrors).toEqual([]);
  });

  it('isolates a check that throws instead of crashing the scan', () => {
    const checks: Check[] = [
      makeCheck('OK', () => [makeFinding('OK')]),
      makeCheck('BROKEN', () => {
        throw new Error('boom');
      }),
    ];

    const result = runChecks(EMPTY_MODEL, checks);

    expect(result.checksRun).toEqual(['OK']);
    expect(result.internalErrors).toEqual([{ checkId: 'BROKEN', message: 'boom' }]);
    expect(result.findings.some((f) => f.checkId === 'OK')).toBe(true);
    const errorFinding = result.findings.find((f) => f.checkId === 'BROKEN');
    expect(errorFinding?.severity).toBe('info');
    expect(errorFinding?.message).toContain('boom');
  });

  it('honors --only, running just the listed checks', () => {
    const checks: Check[] = [
      makeCheck('A', () => [makeFinding('A')]),
      makeCheck('B', () => [makeFinding('B')]),
    ];

    const result = runChecks(EMPTY_MODEL, checks, { only: ['A'] });

    expect(result.checksRun).toEqual(['A']);
    expect(result.checksSkipped).toEqual(['B']);
    expect(result.findings).toHaveLength(1);
  });

  it('honors --skip, excluding the listed checks', () => {
    const checks: Check[] = [
      makeCheck('A', () => [makeFinding('A')]),
      makeCheck('B', () => [makeFinding('B')]),
    ];

    const result = runChecks(EMPTY_MODEL, checks, { skip: ['B'] });

    expect(result.checksRun).toEqual(['A']);
    expect(result.checksSkipped).toEqual(['B']);
  });

  it('returns no findings for an empty check registry', () => {
    const result = runChecks(EMPTY_MODEL, []);

    expect(result.findings).toEqual([]);
    expect(result.checksRun).toEqual([]);
  });

  // PROPOSED_FIXES.md 2.8 — a check that reads keys only one profile's
  // config format can contain is not applicable under any other profile.
  it('reports a check outside its appliesToProfiles as not applicable instead of running it', () => {
    const run = vi.fn(() => [makeFinding('DEFAULT_ONLY')]);
    const checks: Check[] = [
      { ...makeCheck('DEFAULT_ONLY', run), appliesToProfiles: ['default'] },
      makeCheck('ANY', () => [makeFinding('ANY')]),
    ];

    const result = runChecks(EMPTY_MODEL, checks, { profile: 'mcp' });

    expect(run).not.toHaveBeenCalled();
    expect(result.checksRun).toEqual(['ANY']);
    expect(result.checksNotApplicable).toEqual(['DEFAULT_ONLY']);
    expect(result.checksSkipped).toEqual([]);
    expect(result.findings.map((f) => f.checkId)).toEqual(['ANY']);
  });

  it('runs a profile-scoped check under a profile it lists', () => {
    const checks: Check[] = [
      {
        ...makeCheck('DEFAULT_ONLY', () => [makeFinding('DEFAULT_ONLY')]),
        appliesToProfiles: ['default'],
      },
    ];

    const result = runChecks(EMPTY_MODEL, checks, { profile: 'default' });

    expect(result.checksRun).toEqual(['DEFAULT_ONLY']);
    expect(result.checksNotApplicable).toEqual([]);
  });

  it('runs every check when no profile is given (plugin/test callers)', () => {
    const checks: Check[] = [
      { ...makeCheck('DEFAULT_ONLY', () => []), appliesToProfiles: ['default'] },
    ];

    expect(runChecks(EMPTY_MODEL, checks).checksRun).toEqual(['DEFAULT_ONLY']);
  });
});
