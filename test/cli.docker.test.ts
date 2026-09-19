import { execFileSync } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../src/cli.js';

// improvement_plan.md 3.3 (Phase 20, --docker), against a real container
// — the DoD's own "(if feasible in CI)" hedge; feasible on GitHub
// Actions' ubuntu-latest runners (Docker pre-installed, daemon running
// by default), same as this environment. Gracefully skipped wherever
// Docker isn't available. A missing-container error goes through
// commander's command.error()/process.exit() path and was verified
// manually instead, same convention as every other cli.*.test.ts file.
function isDockerAvailable(): boolean {
  try {
    execFileSync('docker', ['info'], { stdio: 'ignore', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

const dockerAvailable = isDockerAvailable();
const CONTAINER_NAME = 'chaperone-cli-docker-test';

describe.skipIf(!dockerAvailable)('cli scan — --docker, against a real container', () => {
  let logSpy: MockInstance<typeof console.log>;

  beforeAll(() => {
    try {
      execFileSync('docker', ['rm', '-f', CONTAINER_NAME], { stdio: 'ignore' });
    } catch {
      // no leftover container from a previous run — fine.
    }
    execFileSync(
      'docker',
      ['run', '-d', '--name', CONTAINER_NAME, 'busybox:latest', 'sleep', '3600'],
      { stdio: 'ignore', timeout: 60_000 },
    );
    execFileSync('docker', ['cp', 'test/fixtures/clean-agent/.', `${CONTAINER_NAME}:/agent-root`]);
  }, 60_000);

  afterAll(() => {
    try {
      execFileSync('docker', ['rm', '-f', CONTAINER_NAME], { stdio: 'ignore' });
    } catch {
      // best-effort cleanup
    }
  }, 30_000);

  it('scans a real container filesystem via docker cp and produces a real report', () => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      run([
        'node',
        'chaperone',
        'scan',
        '--docker',
        `${CONTAINER_NAME}:/agent-root`,
        '--format',
        'json',
      ]);

      const printed = logSpy.mock.calls[0]?.[0] as string;
      const report = JSON.parse(printed) as { target: string; targetRootResolved: boolean };
      expect(report.targetRootResolved).toBe(true);
      expect(report.target).toBe(`docker:${CONTAINER_NAME}:/agent-root`);
    } finally {
      logSpy.mockRestore();
    }
  }, 30_000);

  it('defaults to the container root when no path is given', () => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      run(['node', 'chaperone', 'scan', '--docker', CONTAINER_NAME, '--format', 'json']);

      const printed = logSpy.mock.calls[0]?.[0] as string;
      const report = JSON.parse(printed) as { targetRootResolved: boolean };
      // /agent-root is nested one level below the container root here,
      // so config.yaml isn't found directly at "/" — still resolves
      // (an explicit --docker target always does), just no findings.
      expect(report.targetRootResolved).toBe(true);
    } finally {
      logSpy.mockRestore();
    }
  }, 30_000);
});
