import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { errorMessage } from './errors.js';

// Docker-aware scanning (improvement_plan.md 3.3/Phase 20). The one
// deliberate place in this codebase that spawns an external process —
// a real, considered exception to the "no subprocess" posture the git-
// shelling question (improvement_plan.md 1.13/Phase 12) explicitly
// declined for a simpler case. Justified here because the whole feature
// is meaningless without it (there is no way to read a container's
// filesystem from the host other than asking the Docker daemon), and
// scoped tightly to minimize the new risk surface: exactly one
// subprocess call (`docker cp`, read-only with respect to the
// container), argv-array invocation (never a shell string — no
// injection surface from a container name/path), and a hard timeout so
// a hung daemon can never hang `chaperone scan` indefinitely. See
// DECISIONS.md, Phase 20.
//
// `docker cp` (not `docker exec`) deliberately: it reads a container's
// filesystem directly from its image/writable layers, so it works on a
// stopped container and never depends on a shell (or any binary at all)
// existing inside it — `docker exec sh -c '...'` would require both.

const DOCKER_CP_TIMEOUT_MS = 30_000;

/** `execFileSync`'s thrown error carries the subprocess's captured stderr — surfacing it directly is far more useful than the generic "Command failed" message. */
function isNodeExecError(err: unknown): err is Error & { stderr: Buffer } {
  return (
    err instanceof Error && 'stderr' in err && Buffer.isBuffer((err as { stderr: unknown }).stderr)
  );
}

/** Splits `container[:path]` into its parts — `path` defaults to `/`, the container's root. */
export function parseDockerRef(ref: string): { container: string; containerPath: string } {
  const colonIndex = ref.indexOf(':');
  if (colonIndex === -1) {
    return { container: ref, containerPath: '/' };
  }
  return { container: ref.slice(0, colonIndex), containerPath: ref.slice(colonIndex + 1) || '/' };
}

export interface ExtractedDockerSource {
  /** A local, temporary read-only copy of the container path — safe to pass to discoverAgent as targetPath. */
  localDir: string;
  /** Removes the temporary copy. Always call this, even on failure — via try/finally at the call site. */
  cleanup: () => void;
}

/**
 * Copies `container:path`'s contents out to a fresh local temp
 * directory via `docker cp`, so the existing, already-tested local-
 * filesystem discovery pipeline can run against it completely
 * unmodified — no fs call anywhere in discovery/ needs to know or care
 * that its source was ever a container. Throws with a clear message on
 * any failure (docker not installed, daemon not running, container/path
 * not found, or the command exceeding a 30s timeout) — the caller turns
 * that into a clean `command.error()`, the same pattern every other
 * explicit-source flag (`--config`, `--baseline`) in this CLI follows.
 */
export function extractDockerSource(ref: string): ExtractedDockerSource {
  const { container, containerPath } = parseDockerRef(ref);
  const localDir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-docker-'));
  try {
    // Trailing `/.` copies the directory's *contents* into localDir,
    // rather than creating a nested subdirectory named after the last
    // path segment (`docker cp`'s own documented behavior).
    const sourcePath = containerPath.endsWith('/') ? `${containerPath}.` : `${containerPath}/.`;
    execFileSync('docker', ['cp', `${container}:${sourcePath}`, localDir], {
      stdio: ['ignore', 'ignore', 'pipe'],
      timeout: DOCKER_CP_TIMEOUT_MS,
    });
  } catch (err) {
    rmSync(localDir, { recursive: true, force: true });
    const stderrText = isNodeExecError(err) ? err.stderr.toString('utf8').trim() : '';
    const detail = stderrText.length > 0 ? stderrText : errorMessage(err);
    throw new Error(
      `could not read '${containerPath}' from container '${container}' via docker cp: ${detail}`,
      { cause: err },
    );
  }
  return {
    localDir,
    cleanup: () => {
      rmSync(localDir, { recursive: true, force: true });
    },
  };
}
