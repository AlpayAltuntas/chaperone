import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import type { InspectedEntry, Skill, SkippedEntry, SkillProvenance } from '../model/types.js';
import { errorMessage } from './errors.js';
import { isRecord } from './jsonUtils.js';

const MANIFEST_FILENAMES = ['package.json', 'skill.json', 'skill.yaml', 'skill.yml'];
const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts']);
const LOCKFILE_NAMES = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
const MAX_SOURCE_FILE_BYTES = 256 * 1024;
const MAX_SCAN_DEPTH = 4;

const SHELL_EXEC_PATTERNS = [/child_process/, /\bexecSync?\(/, /\bspawnSync?\(/];
const FS_WRITE_PATTERNS = [
  /\bfs\.(writeFile|unlink|rm|rmdir|appendFile)/,
  /require\(['"]fs['"]\)/,
  /from\s+['"]fs['"]/,
];
const NETWORK_PATTERNS = [
  /\bfetch\(/,
  /\bhttps?\.request\(/,
  /require\(['"](?:https?|node-fetch|axios)['"]\)/,
];
const DESTRUCTIVE_KEYWORDS = ['delete', 'send', 'transfer', 'purchase', 'deploy', 'remove', 'pay'];
const DANGEROUS_INSTALL_PATTERNS = [
  /curl[^\n]*\|\s*(?:ba)?sh/i,
  /wget[^\n]*\|\s*(?:ba)?sh/i,
  /\bsudo\b/i,
  /\bapt-get install\b/i,
  /\bbrew install\b/i,
];

export interface SkillsScanResult {
  skills: Skill[];
  inspected: InspectedEntry[];
  skipped: SkippedEntry[];
}

/** Enumerates and parses every skill/plugin under a skills directory into normalized Skill records. */
export function scanSkills(skillsDir: string): SkillsScanResult {
  const inspected: InspectedEntry[] = [];
  const skipped: SkippedEntry[] = [];
  const skills: Skill[] = [];

  let entryNames: string[];
  try {
    entryNames = readdirSync(skillsDir).filter((name) => isDirectory(path.join(skillsDir, name)));
  } catch {
    return { skills, inspected, skipped };
  }

  for (const name of entryNames.sort()) {
    skills.push(scanOneSkill(name, path.join(skillsDir, name), inspected, skipped));
  }

  return { skills, inspected, skipped };
}

function scanOneSkill(
  dirName: string,
  dir: string,
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): Skill {
  const manifestPath = findFirstExisting(dir, MANIFEST_FILENAMES);
  const manifest = manifestPath ? readManifest(manifestPath, inspected, skipped) : null;

  const sourceFiles = listSourceFiles(dir);
  const combinedSource = readSourceFiles(sourceFiles, inspected, skipped);

  const capabilities = {
    shellExec: SHELL_EXEC_PATTERNS.some((re) => re.test(combinedSource)),
    fileSystemAccess: FS_WRITE_PATTERNS.some((re) => re.test(combinedSource)),
    networkAccess: NETWORK_PATTERNS.some((re) => re.test(combinedSource)),
    destructiveKeywords: DESTRUCTIVE_KEYWORDS.filter((kw) =>
      new RegExp(`\\b${kw}\\b`, 'i').test(combinedSource),
    ),
  };

  const packageJsonPath = manifestPath?.endsWith('package.json')
    ? manifestPath
    : findFirstExisting(dir, ['package.json']);
  const dependencies = {
    manifestPath: packageJsonPath,
    lockfilePath: findFirstExisting(dir, LOCKFILE_NAMES),
  };
  if (dependencies.lockfilePath) {
    inspected.push({ path: dependencies.lockfilePath, kind: 'skill-lockfile' });
  }

  const installScripts = scanInstallScripts(dir, manifest, inspected, skipped);
  const provenance = extractProvenance(manifest);

  const name = manifest && typeof manifest['name'] === 'string' ? manifest['name'] : dirName;

  return { name, dir, manifestPath, capabilities, provenance, dependencies, installScripts };
}

function readManifest(
  manifestPath: string,
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): Record<string, unknown> | null {
  try {
    const raw = readFileSync(manifestPath, 'utf8');
    const parsed: unknown = manifestPath.endsWith('.json') ? JSON.parse(raw) : YAML.parse(raw);
    inspected.push({ path: manifestPath, kind: 'skill-manifest' });
    return isRecord(parsed) ? parsed : null;
  } catch (err) {
    skipped.push({ path: manifestPath, reason: `unparseable manifest: ${errorMessage(err)}` });
    return null;
  }
}

function listSourceFiles(dir: string, depth = 0): string[] {
  if (depth > MAX_SCAN_DEPTH) {
    return [];
  }
  let entries: import('node:fs').Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }

  const files: string[] = [];
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) {
      continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listSourceFiles(full, depth + 1));
    } else if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
      files.push(full);
    }
  }
  return files;
}

function readSourceFiles(
  files: string[],
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): string {
  let combined = '';
  for (const file of files) {
    try {
      const stat = statSync(file);
      if (stat.size > MAX_SOURCE_FILE_BYTES) {
        skipped.push({ path: file, reason: 'source file too large to scan (>256KB)' });
        continue;
      }
      combined += readFileSync(file, 'utf8') + '\n';
      inspected.push({ path: file, kind: 'skill-source' });
    } catch (err) {
      skipped.push({ path: file, reason: `unreadable source: ${errorMessage(err)}` });
    }
  }
  return combined;
}

function scanInstallScripts(
  dir: string,
  manifest: Record<string, unknown> | null,
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): { scripts: Array<{ path: string; dangerousPatterns: string[] }> } {
  const results: Array<{ path: string; dangerousPatterns: string[] }> = [];

  const npmScripts = manifest && isRecord(manifest['scripts']) ? manifest['scripts'] : null;
  if (npmScripts) {
    for (const key of ['preinstall', 'install', 'postinstall']) {
      const value = npmScripts[key];
      if (typeof value === 'string') {
        const matched = matchDangerousPatterns(value);
        if (matched.length > 0) {
          results.push({ path: `package.json#scripts.${key}`, dangerousPatterns: matched });
        }
      }
    }
  }

  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    entries = [];
  }

  for (const entry of entries) {
    const isShellScript = entry.endsWith('.sh');
    const isReadme = /^readme/i.test(entry);
    if (!isShellScript && !isReadme) {
      continue;
    }
    const full = path.join(dir, entry);
    try {
      const content = readFileSync(full, 'utf8');
      inspected.push({ path: full, kind: 'skill-install-script' });
      const matched = matchDangerousPatterns(content);
      if (matched.length > 0) {
        results.push({ path: full, dangerousPatterns: matched });
      }
    } catch (err) {
      skipped.push({ path: full, reason: `unreadable install script/doc: ${errorMessage(err)}` });
    }
  }

  return { scripts: results };
}

function matchDangerousPatterns(text: string): string[] {
  const matches: string[] = [];
  for (const re of DANGEROUS_INSTALL_PATTERNS) {
    const match = re.exec(text);
    if (match) {
      matches.push(match[0]);
    }
  }
  return matches;
}

function extractProvenance(manifest: Record<string, unknown> | null): SkillProvenance {
  if (!manifest) {
    return { sourceUrl: null, pinnedRef: null, author: null };
  }

  const repository = manifest['repository'];
  const sourceUrl =
    typeof repository === 'string'
      ? repository
      : isRecord(repository) && typeof repository['url'] === 'string'
        ? repository['url']
        : typeof manifest['source'] === 'string'
          ? manifest['source']
          : typeof manifest['homepage'] === 'string'
            ? manifest['homepage']
            : null;

  const authorField = manifest['author'];
  const author =
    typeof authorField === 'string'
      ? authorField
      : isRecord(authorField) && typeof authorField['name'] === 'string'
        ? authorField['name']
        : null;

  const version = typeof manifest['version'] === 'string' ? manifest['version'] : null;
  const ref =
    typeof manifest['ref'] === 'string'
      ? manifest['ref']
      : typeof manifest['gitRef'] === 'string'
        ? manifest['gitRef']
        : null;

  let pinnedRef: boolean | null = null;
  if (ref !== null) {
    pinnedRef = /^[0-9a-f]{7,40}$/i.test(ref) || /^\d+\.\d+\.\d+/.test(ref);
  } else if (version !== null) {
    pinnedRef = version !== 'latest' && /^\d+\.\d+\.\d+/.test(version);
  }

  return { sourceUrl, pinnedRef, author };
}

function findFirstExisting(dir: string, filenames: string[]): string | null {
  for (const filename of filenames) {
    const candidate = path.join(dir, filename);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function isDirectory(candidate: string): boolean {
  try {
    return statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}
