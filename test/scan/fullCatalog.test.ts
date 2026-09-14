import { chmodSync, cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { runChecks } from '../../src/engine/index.js';
import { computeScore } from '../../src/engine/severity.js';

/**
 * The Phase 3 "runnable check" from instruction.md §12: the full check
 * catalog, run against both named fixtures, must produce exactly the
 * expected finding set.
 *
 * This test works on a CHMOD'D COPY of each fixture, not the committed
 * files directly, for two reasons: (1) it must never mutate the real
 * working tree during a test run, and (2) git only preserves the
 * executable bit, so a file's checked-out mode (0600 vs 0644) is not
 * portable across machines/CI — see DECISIONS.md, Phase 1/3. Copying to a
 * temp dir and setting permissions explicitly makes every check,
 * including the permission-dependent ones (CHAP-SEC-003, part of
 * CHAP-SEC-004), fully deterministic here.
 */

// The real fixtures sit inside the Chaperone repo's own git tree (that's
// intentional — see DECISIONS.md, Phase 1/3), which CHAP-SEC-002 depends
// on. A plain temp-dir copy loses that context, so we simulate it: an
// empty ".git" directory (existence is all detectGitContext checks) and a
// .gitignore that does NOT cover config.yaml, matching the real repo.
function copyFixtureWithPermissions(name: string, mode: number): string {
  const src = path.join('test', 'fixtures', name);
  const dest = mkdtempSync(path.join(os.tmpdir(), `chaperone-fullcatalog-${name}-`));
  cpSync(src, dest, { recursive: true });
  mkdirSync(path.join(dest, '.git'));
  writeFileSync(path.join(dest, '.gitignore'), 'node_modules/\ndist/\n');
  chmodSync(path.join(dest, 'config.yaml'), mode);
  chmodSync(path.join(dest, 'logs', 'agent.log'), mode);
  return dest;
}

function countByCheckId(findings: readonly { checkId: string }[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    counts[finding.checkId] = (counts[finding.checkId] ?? 0) + 1;
  }
  return counts;
}

describe('full check catalog — vulnerable-agent (chmod 644: readable)', () => {
  let dir: string;

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('reports exactly the expected finding per check', () => {
    dir = copyFixtureWithPermissions('vulnerable-agent', 0o644);
    const { model } = discoverAgent({ targetPath: dir });
    const { findings, internalErrors } = runChecks(model, ALL_CHECKS);

    expect(internalErrors).toEqual([]);
    expect(countByCheckId(findings)).toEqual({
      'CHAP-SEC-001': 2,
      'CHAP-SEC-002': 1,
      'CHAP-SEC-003': 1,
      'CHAP-SEC-004': 1,
      'CHAP-AGY-001': 2,
      'CHAP-AGY-002': 1,
      'CHAP-AGY-003': 1,
      'CHAP-AGY-004': 2,
      'CHAP-SUP-001': 4,
      'CHAP-SUP-002': 4,
      'CHAP-SUP-003': 4,
      'CHAP-SUP-004': 2,
      'CHAP-INJ-001': 1,
      'CHAP-INJ-002': 1,
      'CHAP-INJ-003': 1,
      'CHAP-INJ-004': 1,
      'CHAP-NET-001': 1,
      'CHAP-NET-002': 1,
      'CHAP-NET-003': 1,
      'CHAP-OBS-001': 1,
      'CHAP-OBS-002': 1,
      'CHAP-OBS-003': 1,
    });
    expect(findings).toHaveLength(35);
    // 3*25 (critical) + 17*15 (high) + 14*7 (medium) + 1*3 (low) = 431 -> floored at 0.
    expect(computeScore(findings)).toEqual({ score: 0, band: 'F' });
  });
});

describe('full check catalog — clean-agent (chmod 600: locked down)', () => {
  let dir: string;

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('reports only CHAP-SUP-003 (a documented v1 limitation, not a defect)', () => {
    dir = copyFixtureWithPermissions('clean-agent', 0o600);
    const { model } = discoverAgent({ targetPath: dir });
    const { findings, internalErrors } = runChecks(model, ALL_CHECKS);

    expect(internalErrors).toEqual([]);
    expect(countByCheckId(findings)).toEqual({ 'CHAP-SUP-003': 3 });
    // Illustrates the CHECKS.md caveat: even a hardened install doesn't
    // score a full 100, purely because of CHAP-SUP-003's deliberately weak
    // v1 heuristic (3 High findings = 3*15 = 45 deducted).
    expect(computeScore(findings)).toEqual({ score: 55, band: 'D' });
  });
});
