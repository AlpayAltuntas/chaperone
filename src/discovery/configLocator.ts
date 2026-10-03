import { existsSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const CONFIG_FILENAMES: readonly string[] = ['config.yaml', 'config.yml', 'config.json'];

// Illustrative install-root conventions for Clawdbot/Moltbot/OpenClaw-style
// agents, probed only when the user omits an explicit target path. No
// canonical spec exists for these fictional example agents, so this list is
// a documented assumption (see DECISIONS.md) rather than a verified
// standard — `chaperone scan <path>` with an explicit path is the
// primary, reliable way to point Chaperone at a real install.
export const DEFAULT_ROOTS: readonly string[] = [
  '.clawd',
  'clawd',
  path.join('.config', 'clawdbot'),
  '.moltbot',
  path.join('.config', 'moltbot'),
  '.openclaw',
  path.join('.config', 'openclaw'),
];

export type ExplicitTargetResolution = { root: string } | { root: null; reason: string };

/**
 * Validates an explicit `scan <path>` argument (PROPOSED_FIXES.md 2.1).
 * A nonexistent path, or a file that isn't one of `configFilenames`,
 * can't be scanned — reported with a reason instead of resolving to a
 * phantom root whose empty model would grade "A". A path to one of
 * the config files themselves (`scan ~/clawd/config.yaml`, a natural
 * first attempt) resolves to its containing directory.
 */
export function resolveExplicitTarget(
  explicitPath: string,
  configFilenames: readonly string[],
): ExplicitTargetResolution {
  const resolved = path.resolve(explicitPath);
  let isDirectory: boolean;
  try {
    isDirectory = statSync(resolved).isDirectory();
  } catch {
    return { root: null, reason: 'path does not exist' };
  }
  if (isDirectory) {
    return { root: resolved };
  }
  if (configFilenames.includes(path.basename(resolved))) {
    return { root: path.dirname(resolved) };
  }
  return {
    root: null,
    reason: `path is a file, not an agent directory (pass the directory containing ${configFilenames.join('/')})`,
  };
}

/** Probes the default install roots under $HOME (used only when no explicit path is given); returns the first that exists. */
export function probeDefaultRoot(): string | null {
  const home = os.homedir();
  for (const rel of DEFAULT_ROOTS) {
    const candidate = path.join(home, rel);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

/** Finds the config file directly inside a resolved root, trying known filenames in order. */
export function locateConfigFile(root: string): string | null {
  for (const filename of CONFIG_FILENAMES) {
    const candidate = path.join(root, filename);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}
