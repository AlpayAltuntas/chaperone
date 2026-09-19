import { describe, expect, it } from 'vitest';
import { runChecks } from '../../src/engine/index.js';
import type { Check } from '../../src/engine/types.js';
import type { AgentModel, Finding } from '../../src/model/types.js';

const EMPTY_MODEL: AgentModel = {
  targetRoot: '/fake',
  config: { path: null, format: null, data: null, secretFields: [] },
  sidecarSecretFiles: [],
  git: {
    hasAncestorGitDir: false,
    gitDirPath: null,
    gitRootPath: null,
    gitignorePatterns: [],
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
  return { id, title: id, severity: 'low', category: 'secrets', owasp: 'LLM06', run };
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
});
