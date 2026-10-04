import { readFileSync } from 'node:fs';
import path from 'node:path';

// Python dependency manifests (PROPOSED_FIXES.md 3.4): declared names and
// specifiers, plus whether a lockfile pins exact, hashed versions. Feeds
// CHAP-SUP-002 ("dependencies with no lockfile"). Deliberately small
// parsers, not full PEP 508 / TOML implementations.

export const PYTHON_MANIFESTS = ['requirements.txt', 'pyproject.toml'];
export const PYTHON_LOCKFILES = ['poetry.lock', 'uv.lock', 'Pipfile.lock', 'pdm.lock'];

const REQUIREMENT_NAME = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$/;

function parseRequirement(line: string): [string, string] | null {
  const trimmed = line.replace(/\s+#.*$/, '').trim();
  if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith('-')) {
    return null;
  }
  const match = REQUIREMENT_NAME.exec(trimmed);
  if (match?.[1] === undefined) {
    return null;
  }
  const specifier =
    (match[2] ?? '').split(';')[0]?.replace(/\\$/, '').split(/\s+--/)[0]?.trim() ?? '';
  return [match[1].toLowerCase(), specifier];
}

export interface PythonDependencies {
  manifestPath: string;
  versionsByName: Record<string, string>;
  /** A requirements file whose every entry carries `--hash=` is its own lockfile. */
  hashPinned: boolean;
}

/** `requirements.txt`: one requirement per line; `-r`/`-e`/option lines and comments ignored. */
export function parseRequirementsTxt(source: string): {
  versionsByName: Record<string, string>;
  hashPinned: boolean;
} {
  const versionsByName: Record<string, string> = {};
  // Continuation lines (`\`) join a requirement with its `--hash=` options.
  const logical = source.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  let requirements = 0;
  let hashed = 0;
  for (const line of logical) {
    const parsed = parseRequirement(line);
    if (parsed !== null) {
      versionsByName[parsed[0]] = parsed[1];
      requirements++;
      if (line.includes('--hash=')) {
        hashed++;
      }
    }
  }
  return { versionsByName, hashPinned: requirements > 0 && hashed === requirements };
}

/** `pyproject.toml`: `[project] dependencies = [...]` and `[tool.poetry.dependencies]` tables. */
export function parsePyprojectToml(source: string): Record<string, string> {
  const versionsByName: Record<string, string> = {};
  const project = /^\[project\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(source)?.[1] ?? '';
  const list = /^dependencies\s*=\s*\[([\s\S]*?)\]/m.exec(project)?.[1] ?? '';
  for (const item of list.matchAll(/["']([^"']+)["']/g)) {
    const parsed = parseRequirement(item[1] ?? '');
    if (parsed !== null) {
      versionsByName[parsed[0]] = parsed[1];
    }
  }
  const poetry =
    /^\[tool\.poetry\.dependencies\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(source)?.[1] ?? '';
  for (const line of poetry.split(/\r?\n/)) {
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+)$/.exec(line.trim());
    if (match?.[1] !== undefined && match[1].toLowerCase() !== 'python') {
      versionsByName[match[1].toLowerCase()] = (match[2] ?? '').replace(/^["']|["']$/g, '');
    }
  }
  return versionsByName;
}

/** The first Python manifest in a skill directory, parsed; null when there is none or it can't be read. */
export function readPythonDependencies(dir: string): PythonDependencies | null {
  for (const name of PYTHON_MANIFESTS) {
    const manifestPath = path.join(dir, name);
    let source: string;
    try {
      source = readFileSync(manifestPath, 'utf8');
    } catch {
      continue;
    }
    if (name === 'requirements.txt') {
      const parsed = parseRequirementsTxt(source);
      return { manifestPath, ...parsed };
    }
    return { manifestPath, versionsByName: parsePyprojectToml(source), hashPinned: false };
  }
  return null;
}
