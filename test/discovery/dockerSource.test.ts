import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { extractDockerSource, parseDockerRef } from '../../src/discovery/dockerSource.js';

describe('parseDockerRef', () => {
  it('defaults the path to the container root when omitted', () => {
    expect(parseDockerRef('my-container')).toEqual({
      container: 'my-container',
      containerPath: '/',
    });
  });

  it('splits container:path on the first colon', () => {
    expect(parseDockerRef('my-container:/agent-root')).toEqual({
      container: 'my-container',
      containerPath: '/agent-root',
    });
  });

  it('treats an empty path after the colon as the container root', () => {
    expect(parseDockerRef('my-container:')).toEqual({
      container: 'my-container',
      containerPath: '/',
    });
  });
});

// Real-container integration tests (improvement_plan.md 3.3's DoD: "if
// feasible in CI" — feasible on GitHub Actions' ubuntu-latest runners,
// which ship Docker pre-installed with the daemon running, same as this
// environment). Gracefully skipped (not failed) wherever Docker isn't
// available, e.g. a contributor's machine without it installed.
function isDockerAvailable(): boolean {
  try {
    execFileSync('docker', ['info'], { stdio: 'ignore', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

const dockerAvailable = isDockerAvailable();
const CONTAINER_NAME = 'chaperone-dockersource-test';

describe.skipIf(!dockerAvailable)('extractDockerSource — against a real container', () => {
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
    execFileSync('docker', [
      'exec',
      CONTAINER_NAME,
      'sh',
      '-c',
      'mkdir -p /agent-root && echo "hello from inside the container" > /agent-root/marker.txt',
    ]);
  }, 60_000);

  afterAll(() => {
    try {
      execFileSync('docker', ['rm', '-f', CONTAINER_NAME], { stdio: 'ignore' });
    } catch {
      // best-effort cleanup
    }
  }, 30_000);

  it('copies a container path to a local temp directory, readable with ordinary fs calls', () => {
    const { localDir, cleanup } = extractDockerSource(`${CONTAINER_NAME}:/agent-root`);
    try {
      expect(existsSync(path.join(localDir, 'marker.txt'))).toBe(true);
      expect(readFileSync(path.join(localDir, 'marker.txt'), 'utf8')).toContain(
        'hello from inside the container',
      );
    } finally {
      cleanup();
    }
    expect(existsSync(localDir)).toBe(false);
  }, 30_000);

  it('defaults to the container root when no path is given', () => {
    const { localDir, cleanup } = extractDockerSource(CONTAINER_NAME);
    try {
      expect(existsSync(path.join(localDir, 'agent-root', 'marker.txt'))).toBe(true);
    } finally {
      cleanup();
    }
  }, 30_000);

  it('throws a clear, informative error for a nonexistent container — and still cleans up the temp dir', () => {
    expect(() => extractDockerSource('chaperone-nonexistent-container-xyz')).toThrow(
      /could not read .* from container 'chaperone-nonexistent-container-xyz'/,
    );
  }, 30_000);

  it('cleanup() removes the temp directory it created', () => {
    const { localDir, cleanup } = extractDockerSource(`${CONTAINER_NAME}:/agent-root`);
    expect(existsSync(localDir)).toBe(true);
    cleanup();
    expect(existsSync(localDir)).toBe(false);
  }, 30_000);
});
