import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      // Only src/**/*.ts — test/fixtures/** is inert sample data the
      // checks scan, not our own code, and lives under test/ anyway.
      include: ['src/**/*.ts'],
      reporter: ['text', 'text-summary', 'json-summary', 'html'],
      reportsDirectory: './coverage',
    },
  },
});
