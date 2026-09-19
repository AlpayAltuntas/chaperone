import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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
  // Sidecar secret file / memory dir (improvement_plan.md Phase 5) only
  // exist in vulnerable-agent — chmod them too when present, same
  // rationale as config.yaml/agent.log above. The memory dir needs the
  // directory-appropriate mode (execute bit wherever a read bit is set,
  // e.g. 644 -> 755) — chmod'ing a directory to a file mode like 0o644
  // strips the execute bit and makes it untraversable (breaks even our
  // own rmSync cleanup, not just the check under test).
  const dirMode = mode | ((mode & 0o444) >> 2);
  chmodIfExists(path.join(dest, 'secrets.yaml'), mode);
  chmodIfExists(path.join(dest, 'memory'), dirMode);
  return dest;
}

function chmodIfExists(target: string, mode: number): void {
  if (existsSync(target)) {
    chmodSync(target, mode);
  }
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
      'CHAP-SEC-005': 1,
      'CHAP-SEC-006': 1,
      'CHAP-AGY-001': 3,
      'CHAP-AGY-002': 1,
      'CHAP-AGY-003': 2,
      'CHAP-AGY-004': 3,
      'CHAP-SUP-001': 6,
      'CHAP-SUP-002': 6,
      'CHAP-SUP-003': 1,
      'CHAP-SUP-004': 2,
      'CHAP-SUP-005': 1,
      'CHAP-SUP-006': 1,
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
      'CHAP-OBS-004': 1,
    });
    expect(findings).toHaveLength(44);
    // 5*25 (critical) + 20*15 (high) + 18*7 (medium) + 1*3 (low) + 0*0
    // (info) = 554 -> floored at 0. CHAP-SUP-003 (Phase 18) now matches
    // plugin-loader's lodash@^4.17.15 against the offline vulnerability
    // snapshot at real `high` severity, instead of firing `info` on
    // every skill with a manifest.
    expect(computeScore(findings)).toEqual({ score: 0, band: 'F' });
  });
});

describe('full check catalog — clean-agent (chmod 600: locked down)', () => {
  let dir: string;

  // clean-agent's config uses indirect env-var references by design —
  // that's the whole point of the hardened fixture. CHAP-SEC-007
  // (Phase 6) checks whether those variables are actually set in
  // Chaperone's own process environment, so a genuinely clean install
  // means these are set, same as a real operator would have them set
  // for the agent process itself.
  beforeEach(() => {
    vi.stubEnv('ANTHROPIC_API_KEY', 'test-value');
    vi.stubEnv('TELEGRAM_BOT_TOKEN', 'test-value');
    vi.stubEnv('GATEWAY_AUTH_TOKEN', 'test-value');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    vi.unstubAllEnvs();
  });

  it('reports no findings at all — a genuine true negative, unlike CHAP-SUP-003 pre-Phase-18', () => {
    dir = copyFixtureWithPermissions('clean-agent', 0o600);
    const { model } = discoverAgent({ targetPath: dir });
    const { findings, internalErrors } = runChecks(model, ALL_CHECKS);

    expect(internalErrors).toEqual([]);
    // Phase 18: CHAP-SUP-003 now matches real dependency versions
    // against the offline vulnerability snapshot instead of firing on
    // any manifest — weather's lodash@^4.18.2 is a patched version, so
    // this check (and therefore the whole fixture) is finally silent.
    expect(countByCheckId(findings)).toEqual({});
    expect(computeScore(findings)).toEqual({ score: 100, band: 'A' });
  });
});
