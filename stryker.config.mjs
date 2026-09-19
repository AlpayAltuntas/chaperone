// @ts-check
/**
 * Mutation testing (improvement_plan.md 5.4) — a "tests for the test
 * suite" signal: verifies the existing test coverage would actually
 * catch a regression, not just that it currently passes. Explicitly a
 * non-blocking CI signal (`npm run mutation`, wired into CI as a
 * continue-on-error step) — Stryker is slow (it re-runs the relevant
 * tests once per generated mutant), so this is deliberately scoped to a
 * small, high-value subset of the codebase rather than the whole `src/`
 * tree: the same two "small, pure, input-shape-sensitive" modules
 * improvement_plan.md 5.2 already named and property-fuzz-tests
 * (`configParser.ts`, `gitignoreMatch.ts`) — the parts of this codebase
 * most worth verifying test quality against, and cheap enough to run on
 * every push. See DECISIONS.md, Phase 23 (5.4).
 *
 * @type {import('@stryker-mutator/api/core').PartialStrykerOptions}
 */
const config = {
  packageManager: 'npm',
  testRunner: 'vitest',
  vitest: {
    // A narrower vitest config, scoped to just the test files that
    // exercise the two mutated modules — see vitest.stryker.config.ts's
    // own doc comment for why (Stryker's initial dry run otherwise
    // fails on this project's process.chdir()-based tests, which Node
    // disallows inside the worker threads Stryker always runs in).
    configFile: 'vitest.stryker.config.ts',
  },
  reporters: ['clear-text', 'progress', 'html'],
  htmlReporter: {
    fileName: 'reports/mutation/index.html',
  },
  mutate: ['src/discovery/configParser.ts', 'src/checks/shared/gitignoreMatch.ts'],
  coverageAnalysis: 'perTest',
  thresholds: {
    high: 90,
    low: 70,
    break: null,
  },
};

export default config;
