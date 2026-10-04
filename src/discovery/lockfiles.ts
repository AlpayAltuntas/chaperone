import { readFileSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { isRecord } from './jsonUtils.js';

// npm lockfile parsing (PROPOSED_FIXES.md 3.5): the exact versions an
// install resolves to, direct and transitive, so CHAP-SUP-003/007 match
// what is actually installed instead of a specifier's floor.

export interface ResolvedPackage {
  name: string;
  version: string;
}

// A skill's lockfile is small; this bounds a pathological one.
const MAX_RESOLVED = 20_000;

function push(out: ResolvedPackage[], seen: Set<string>, name: string, version: unknown): void {
  if (
    typeof version !== 'string' ||
    !/^\d+\.\d+\.\d+/.test(version) ||
    out.length >= MAX_RESOLVED
  ) {
    return;
  }
  const key = `${name}@${version}`;
  if (!seen.has(key)) {
    seen.add(key);
    out.push({ name, version });
  }
}

/** package-lock.json v2/v3 `packages` (keyed by install path), with v1 `dependencies` as a fallback. */
export function parsePackageLock(source: string): ResolvedPackage[] {
  const parsed = JSON.parse(source) as unknown;
  const out: ResolvedPackage[] = [];
  const seen = new Set<string>();
  if (!isRecord(parsed)) {
    return out;
  }
  const packages = parsed['packages'];
  if (isRecord(packages)) {
    for (const [installPath, info] of Object.entries(packages)) {
      const marker = installPath.lastIndexOf('node_modules/');
      if (marker === -1 || !isRecord(info) || info['link'] === true) {
        continue;
      }
      const name =
        typeof info['name'] === 'string'
          ? info['name']
          : installPath.slice(marker + 'node_modules/'.length);
      push(out, seen, name, info['version']);
    }
    return out;
  }
  const walk = (deps: unknown): void => {
    if (!isRecord(deps)) {
      return;
    }
    for (const [name, info] of Object.entries(deps)) {
      if (isRecord(info)) {
        push(out, seen, name, info['version']);
        walk(info['dependencies']);
      }
    }
  };
  walk(parsed['dependencies']);
  return out;
}

/** yarn.lock v1: `"name@range", name@range:` headers followed by an indented `version "x.y.z"`. */
export function parseYarnLock(source: string): ResolvedPackage[] {
  const out: ResolvedPackage[] = [];
  const seen = new Set<string>();
  let currentName: string | null = null;
  for (const line of source.split(/\r?\n/)) {
    if (line === '' || line.startsWith('#')) {
      continue;
    }
    if (!line.startsWith(' ')) {
      const first = line.replace(/:$/, '').split(',')[0]?.trim().replace(/^"|"$/g, '') ?? '';
      // `@scope/name@range` -> `@scope/name`; `name@range` -> `name`.
      const at = first.indexOf('@', first.startsWith('@') ? 1 : 0);
      currentName = at === -1 ? null : first.slice(0, at);
      continue;
    }
    const version = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line)?.[1];
    if (currentName !== null && version !== undefined) {
      push(out, seen, currentName, version);
      currentName = null;
    }
  }
  return out;
}

/** pnpm-lock.yaml `packages` keys: `/name@1.2.3` (v6), `name@1.2.3` (v9), or `/name/1.2.3` (v5). */
export function parsePnpmLock(source: string): ResolvedPackage[] {
  const parsed = YAML.parse(source) as unknown;
  const out: ResolvedPackage[] = [];
  const seen = new Set<string>();
  const packages = isRecord(parsed) ? parsed['packages'] : undefined;
  if (!isRecord(packages)) {
    return out;
  }
  for (const key of Object.keys(packages)) {
    const bare = key.replace(/^\//, '').replace(/\(.*$/, '');
    const at = bare.lastIndexOf('@');
    if (at > 0) {
      push(out, seen, bare.slice(0, at), bare.slice(at + 1));
      continue;
    }
    const slash = bare.lastIndexOf('/');
    if (slash > 0) {
      push(out, seen, bare.slice(0, slash), bare.slice(slash + 1));
    }
  }
  return out;
}

/** The resolved packages in a lockfile, by its file name; null when it can't be read or parsed. */
export function readLockfile(lockfilePath: string): ResolvedPackage[] | null {
  let source: string;
  try {
    source = readFileSync(lockfilePath, 'utf8');
  } catch {
    return null;
  }
  try {
    switch (path.basename(lockfilePath)) {
      case 'package-lock.json':
      case 'npm-shrinkwrap.json':
        return parsePackageLock(source);
      case 'yarn.lock':
        return parseYarnLock(source);
      case 'pnpm-lock.yaml':
        return parsePnpmLock(source);
      default:
        return null;
    }
  } catch {
    return null;
  }
}
