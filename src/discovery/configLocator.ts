import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const CONFIG_FILENAMES = ['config.yaml', 'config.yml', 'config.json'];

// Illustrative install-root conventions for Clawdbot/Moltbot/OpenClaw-style
// agents, probed only when the user omits an explicit target path. No
// canonical spec exists for these fictional example agents, so this list is
// a documented assumption (see DECISIONS.md) rather than a verified
// standard — `chaperone scan <path>` with an explicit path is the
// primary, reliable way to point Chaperone at a real install.
const DEFAULT_ROOTS = [
  '.clawd',
  'clawd',
  path.join('.config', 'clawdbot'),
  '.moltbot',
  path.join('.config', 'moltbot'),
  '.openclaw',
  path.join('.config', 'openclaw'),
];

/** Resolves the root directory to scan: the explicit path if given, else the first existing default root. */
export function resolveTargetRoot(explicitPath: string | undefined): string | null {
  if (explicitPath !== undefined) {
    return path.resolve(explicitPath);
  }
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
