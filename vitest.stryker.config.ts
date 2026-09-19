import { defineConfig } from 'vitest/config';

// A narrower test scope for Stryker's mutation run (improvement_plan.md
// 5.4) — Stryker's vitest-runner's own initial "dry run" (to map
// coverage before generating any mutant) executes against this config's
// full `include` glob, unfiltered by the `mutate` scope in
// stryker.config.mjs. The project's main vitest.config.ts includes
// every test in test/**/*.test.ts, several of which call
// process.chdir() (e.g. .chaperonerc.json auto-discovery tests) — which
// Node explicitly disallows inside worker threads, and Stryker's runner
// always executes tests inside one. Since mutation testing here is
// deliberately scoped to just configParser.ts/gitignoreMatch.ts (see
// stryker.config.mjs's own doc comment), only the test files that
// actually exercise those two modules need to run at all.
export default defineConfig({
  test: {
    include: [
      'test/discovery/configParser.test.ts',
      'test/discovery/configParser.fuzz.test.ts',
      'test/checks/shared/gitignoreMatch.test.ts',
      'test/checks/shared/gitignoreMatch.fuzz.test.ts',
    ],
    environment: 'node',
  },
});
