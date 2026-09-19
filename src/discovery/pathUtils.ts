import os from 'node:os';
import path from 'node:path';

/**
 * Expands a leading `~` or `~/...` to the user's home directory. A bare
 * config value like `logging: { path: ~/logs/agent.log }` is common —
 * `~` is a shell convention `path.resolve` knows nothing about, so
 * without this it was silently resolved as a literal subdirectory named
 * "~" rather than the user's home directory (see improvement_plan.md 1.4).
 *
 * `homeDir` is an injected parameter (defaulting to `os.homedir()`) so
 * this is unit-testable without depending on or mocking the real home
 * directory — the same pattern used for `isMainModule` in `cli.ts`.
 *
 * `~otheruser`-style expansion (another user's home directory) is
 * intentionally not supported — rare in this context, and resolving an
 * arbitrary username to a home directory is platform-dependent and not
 * worth the added complexity here.
 */
export function expandHome(inputPath: string, homeDir: string = os.homedir()): string {
  if (inputPath === '~') {
    return homeDir;
  }
  if (inputPath.startsWith('~/')) {
    return path.join(homeDir, inputPath.slice(2));
  }
  return inputPath;
}
