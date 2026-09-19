import { chmodSync, cpSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { runChecks } from '../../src/engine/index.js';

/**
 * The 'mcp' profile's own version of fullCatalog.test.ts (Phase 17,
 * improvement_plan.md 3.1's DoD: "produces meaningful findings against a
 * real (not synthetic) config shape"). Run on a chmod'd copy for the
 * same reason fullCatalog.test.ts is — git doesn't preserve an exact
 * checked-out mode, so CHAP-SEC-003 needs an explicit, portable mode.
 */
function copyFixtureWithPermissions(name: string, mode: number): string {
  const src = path.join('test', 'fixtures', name);
  const dest = mktempCopy(name);
  cpSync(src, dest, { recursive: true });
  chmodSync(path.join(dest, '.mcp.json'), mode);
  return dest;
}

function mktempCopy(name: string): string {
  return mkdtempSync(path.join(os.tmpdir(), `chaperone-mcp-fullcatalog-${name}-`));
}

function countByCheckId(findings: readonly { checkId: string }[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    counts[finding.checkId] = (counts[finding.checkId] ?? 0) + 1;
  }
  return counts;
}

describe('mcp profile full catalog — mcp-vulnerable (chmod 644: readable)', () => {
  let dir: string;

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('produces real findings: literal secret in env, unpinned package, world-readable config', () => {
    dir = copyFixtureWithPermissions('mcp-vulnerable', 0o644);
    const { model } = discoverAgent({ targetPath: dir, profile: 'mcp' });
    const { findings, internalErrors } = runChecks(model, ALL_CHECKS);

    expect(internalErrors).toEqual([]);
    // Only checks whose heuristic genuinely transfers to an MCP config
    // fire — CHAP-OBS-001/003 are absence-based and fire regardless of
    // profile (no logging configured, no kill-switch file at the
    // target root); everything channel/gateway/trust/capability-shaped
    // correctly stays silent (see DECISIONS.md, Phase 17).
    expect(countByCheckId(findings)).toEqual({
      'CHAP-SEC-001': 1,
      'CHAP-SEC-003': 1,
      'CHAP-SUP-001': 1,
      'CHAP-OBS-001': 1,
      'CHAP-OBS-003': 1,
    });
  });
});

describe('mcp profile full catalog — mcp-clean (chmod 600: locked down)', () => {
  let dir: string;

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('stays silent on every check whose heuristic applies to the MCP config shape', () => {
    dir = copyFixtureWithPermissions('mcp-clean', 0o600);
    const { model } = discoverAgent({ targetPath: dir, profile: 'mcp' });
    const { findings, internalErrors } = runChecks(model, ALL_CHECKS);

    expect(internalErrors).toEqual([]);
    const relevantFindings = findings.filter((f) =>
      ['CHAP-SEC-001', 'CHAP-SEC-003', 'CHAP-SUP-001'].includes(f.checkId),
    );
    expect(relevantFindings).toEqual([]);
  });
});
