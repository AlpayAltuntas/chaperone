import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { discoverAgent } from '../../src/discovery/index.js';
import { runChecks } from '../../src/engine/index.js';
import { loadPlugin } from '../../src/engine/pluginLoader.js';
import type { Check } from '../../src/engine/types.js';

// PROPOSED_FIXES.md 4.4.
const PLUGINS = path.join('test', 'fixtures', 'plugins');
const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'vulnerable-agent') });

const base = {
  title: 't',
  severity: 'low' as const,
  category: 'supply-chain' as const,
  owasp: 'o',
  detects: 'd',
  heuristic: 'h',
  remediation: 'r',
};

function finding(checkId: string): unknown {
  return {
    checkId,
    title: 't',
    severity: 'low',
    category: 'supply-chain',
    owasp: 'o',
    message: 'm',
    location: { filePath: null, line: null, detail: null },
    remediation: 'r',
  };
}

describe('plugin loading', () => {
  it('loads an ES-module plugin', () => {
    const { checks } = loadPlugin(path.join(PLUGINS, 'esmPlugin.mjs'));
    expect(checks.map((c) => c.id)).toEqual(['CHAP-ESM-001']);
    expect(runChecks(model, checks).findings.length).toBe(model.skills.length);
  });

  it('explains why a top-level-await plugin cannot load', () => {
    expect(() => loadPlugin(path.join(PLUGINS, 'topLevelAwaitPlugin.mjs'))).toThrow(
      /top-level await/,
    );
  });
});

describe('finding validation', () => {
  it.each([
    [
      'impersonates another check',
      () => [finding('CHAP-SEC-001')],
      "may only report its own ID ('CHAP-X-001')",
    ],
    [
      'returns a malformed finding',
      () => [{ checkId: 'CHAP-X-001', severity: 'catastrophic' }],
      'finding 0 is malformed',
    ],
    ['returns a non-array', () => 'nope', 'must return an array'],
  ])('turns a check that %s into an internal-error finding', (_label, produce, message) => {
    const check = { ...base, id: 'CHAP-X-001', run: produce } as unknown as Check;
    const result = runChecks(model, [check]);
    expect(result.internalErrors.map((e) => e.checkId)).toEqual(['CHAP-X-001']);
    expect(result.internalErrors[0]?.message).toContain(message);
    expect(result.findings).toMatchObject([{ checkId: 'CHAP-X-001', severity: 'info' }]);
  });

  it('accepts well-formed findings with the check’s own ID', () => {
    const check: Check = { ...base, id: 'CHAP-X-002', run: () => [finding('CHAP-X-002') as never] };
    expect(runChecks(model, [check]).internalErrors).toEqual([]);
  });
});

describe('model isolation', () => {
  it('gives checks a frozen copy, so one check cannot change what the next sees', () => {
    const mutator: Check = {
      ...base,
      id: 'CHAP-X-003',
      run: (m) => {
        (m.skills as unknown[]).length = 0;
        return [];
      },
    };
    const reader: Check = {
      ...base,
      id: 'CHAP-X-004',
      run: (m) => m.skills.map(() => finding('CHAP-X-004') as never),
    };
    const result = runChecks(model, [mutator, reader]);
    expect(result.internalErrors.map((e) => e.checkId)).toEqual(['CHAP-X-003']);
    expect(result.findings.filter((f) => f.checkId === 'CHAP-X-004')).toHaveLength(
      model.skills.length,
    );
    expect(model.skills.length).toBeGreaterThan(0);
  });
});
