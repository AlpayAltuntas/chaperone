import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { runChecks } from '../../src/engine/index.js';

// improvement_plan.md 5.3 — performance/scale testing. No existing test
// exercises discovery against a large synthetic install; this
// establishes a concrete, checked scale bound now, "before it becomes a
// real complaint rather than after". Not a micro-benchmark (no
// baseline-comparison harness, no statistical rigor) — a single,
// generous wall-clock ceiling that would fail loudly on a real
// algorithmic regression (e.g. an accidental O(n^2) creeping into
// discovery or the check engine) while staying comfortably clear of
// ordinary CI noise.

const SKILL_COUNT = 500;
const TIME_BUDGET_MS = 15_000;

function buildLargeSyntheticInstall(skillCount: number): string {
  const root = mkdtempSync(path.join(os.tmpdir(), 'chaperone-perf-test-'));
  writeFileSync(
    path.join(root, 'config.yaml'),
    ['llm:', '  provider: anthropic', '  api_key: ${ANTHROPIC_API_KEY}', ''].join('\n'),
  );

  const skillsDir = path.join(root, 'skills');
  mkdirSync(skillsDir);
  for (let i = 0; i < skillCount; i++) {
    const name = `skill-${String(i).padStart(4, '0')}`;
    const dir = path.join(skillsDir, name);
    mkdirSync(dir);
    writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({ name, version: '1.0.0', dependencies: { lodash: '4.18.2' } }),
    );
    writeFileSync(
      path.join(dir, 'index.js'),
      [
        `// DUMMY synthetic skill #${String(i)} for the performance/scale test.`,
        'const fetch = globalThis.fetch;',
        `async function run${String(i)}() {`,
        "  const res = await fetch('https://api.example.invalid/data');",
        '  return res.json();',
        '}',
        `module.exports = { run: run${String(i)} };`,
        '',
      ].join('\n'),
    );
  }
  return root;
}

function buildDeeplyNestedSkill(depth: number): string {
  const root = mkdtempSync(path.join(os.tmpdir(), 'chaperone-perf-deep-test-'));
  writeFileSync(path.join(root, 'config.yaml'), 'llm:\n  provider: anthropic\n');

  const skillDir = path.join(root, 'skills', 'deep-skill');
  mkdirSync(skillDir, { recursive: true });
  writeFileSync(path.join(skillDir, 'package.json'), JSON.stringify({ name: 'deep-skill' }));

  let nested = skillDir;
  for (let i = 0; i < depth; i++) {
    nested = path.join(nested, `level-${String(i)}`);
    mkdirSync(nested);
    writeFileSync(path.join(nested, `file-${String(i)}.js`), `module.exports = ${String(i)};\n`);
  }
  return root;
}

describe('performance/scale — a large synthetic install (improvement_plan.md 5.3)', () => {
  let dir: string | undefined;

  afterEach(() => {
    if (dir !== undefined) {
      rmSync(dir, { recursive: true, force: true });
      dir = undefined;
    }
  });

  it(
    `discovers and checks a ${String(SKILL_COUNT)}-skill install within ${String(TIME_BUDGET_MS)}ms`,
    () => {
      dir = buildLargeSyntheticInstall(SKILL_COUNT);

      const start = performance.now();
      const { model, targetRootResolved } = discoverAgent({ targetPath: dir });
      const { findings, internalErrors } = runChecks(model, ALL_CHECKS);
      const elapsedMs = performance.now() - start;

      expect(targetRootResolved).toBe(true);
      expect(model.skills).toHaveLength(SKILL_COUNT);
      expect(internalErrors).toEqual([]);
      // Every skill has a fetch() call with no domain allowlist — a
      // sanity check that checks actually ran across the whole set, not
      // just that discovery finished.
      expect(findings.filter((f) => f.checkId === 'CHAP-AGY-004')).toHaveLength(SKILL_COUNT);

      expect(elapsedMs).toBeLessThan(TIME_BUDGET_MS);
    },
    TIME_BUDGET_MS * 2,
  );

  it(
    'a deeply nested source tree within one skill does not blow up scan time (bounded by MAX_SCAN_DEPTH)',
    () => {
      dir = buildDeeplyNestedSkill(20);

      const start = performance.now();
      const { model, targetRootResolved } = discoverAgent({ targetPath: dir });
      runChecks(model, ALL_CHECKS);
      const elapsedMs = performance.now() - start;

      expect(targetRootResolved).toBe(true);
      expect(model.skills).toHaveLength(1);
      expect(elapsedMs).toBeLessThan(TIME_BUDGET_MS);
    },
    TIME_BUDGET_MS * 2,
  );
});
