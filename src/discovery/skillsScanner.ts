import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import type { InspectedEntry, Skill, SkippedEntry, SkillProvenance } from '../model/types.js';
import {
  detectCapabilities,
  mergeCapabilities,
  type DetectedCapabilities,
} from './astCapabilities.js';
import { errorMessage } from './errors.js';
import { isRecord } from './jsonUtils.js';
import { detectPythonCapabilities } from './pythonCapabilities.js';

const MANIFEST_FILENAMES = ['package.json', 'skill.json', 'skill.yaml', 'skill.yml'];
// JS/TS get the AST-based detectCapabilities (Phase 10); .py gets the
// regex-based detectPythonCapabilities (Phase 16, improvement_plan.md
// 1.9) — dispatched in detectCapabilitiesForFile below.
const JS_TS_SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts']);
const PYTHON_SOURCE_EXTENSIONS = new Set(['.py']);
const SOURCE_EXTENSIONS = new Set([...JS_TS_SOURCE_EXTENSIONS, ...PYTHON_SOURCE_EXTENSIONS]);
const LOCKFILE_NAMES = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
const MAX_SOURCE_FILE_BYTES = 256 * 1024;
const MAX_SCAN_DEPTH = 4;

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
  const sourceContents = readSourceFiles(sourceFiles, inspected, skipped);
  const capabilities = mergeCapabilities(
    sourceContents.map(({ path: filePath, content }) =>
      detectCapabilitiesForFile(filePath, content),
    ),
  );

  const packageJsonPath = manifestPath?.endsWith('package.json')
    ? manifestPath
    : findFirstExisting(dir, ['package.json']);
  const dependencies = {
    manifestPath: packageJsonPath,
    lockfilePath: findFirstExisting(dir, LOCKFILE_NAMES),
    names: extractDependencyNames(packageJsonPath, manifestPath, manifest, inspected, skipped),
  };
  if (dependencies.lockfilePath) {
    inspected.push({ path: dependencies.lockfilePath, kind: 'skill-lockfile' });
  }

  const installScripts = scanInstallScripts(dir, manifest, inspected, skipped);
  const provenance = extractProvenance(manifest);
  const confirmationRequired = extractManifestBoolean(manifest, 'confirmationRequired');
  const domainAllowlist = extractManifestStringArray(manifest, 'domainAllowlist');

  const name = stripControlCharacters(
    manifest && typeof manifest['name'] === 'string' ? manifest['name'] : dirName,
  );

  return {
    name,
    dir,
    manifestPath,
    capabilities,
    provenance,
    dependencies,
    installScripts,
    confirmationRequired,
    domainAllowlist,
  };
}

/**
 * Reads a boolean manifest field, checked both at the manifest's top level
 * and nested under a `capabilities` sub-object — an invented-but-documented
 * convention (see DECISIONS.md, Phase 3) since no real manifest schema
 * exists for these fictional example agents.
 */
function extractManifestBoolean(
  manifest: Record<string, unknown> | null,
  field: string,
): boolean | null {
  if (!manifest) {
    return null;
  }
  if (typeof manifest[field] === 'boolean') {
    return manifest[field];
  }
  const capabilities = manifest['capabilities'];
  if (isRecord(capabilities) && typeof capabilities[field] === 'boolean') {
    return capabilities[field];
  }
  return null;
}

/** Same convention as extractManifestBoolean, for a string-array field. */
function extractManifestStringArray(
  manifest: Record<string, unknown> | null,
  field: string,
): string[] | null {
  if (!manifest) {
    return null;
  }
  const direct = manifest[field];
  if (Array.isArray(direct) && direct.every((v) => typeof v === 'string')) {
    return direct;
  }
  const capabilities = manifest['capabilities'];
  if (isRecord(capabilities)) {
    const nested = capabilities[field];
    if (Array.isArray(nested) && nested.every((v) => typeof v === 'string')) {
      return nested;
    }
  }
  return null;
}

/**
 * Reads package.json's "dependencies" keys — feeds CHAP-SUP-006's
 * typosquat check. Reuses the already-parsed primary manifest when
 * package.json *is* that manifest; otherwise (a skill.json/skill.yaml
 * primary manifest with a separate package.json alongside it) reads
 * package.json specifically, since dependency names only ever come from
 * that file regardless of which manifest format the skill primarily uses.
 */
function extractDependencyNames(
  packageJsonPath: string | null,
  manifestPath: string | null,
  manifest: Record<string, unknown> | null,
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): string[] {
  if (packageJsonPath === null) {
    return [];
  }
  const packageJson =
    packageJsonPath === manifestPath ? manifest : readManifest(packageJsonPath, inspected, skipped);
  const deps =
    packageJson && isRecord(packageJson['dependencies']) ? packageJson['dependencies'] : null;
  return deps ? Object.keys(deps) : [];
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

/** Dispatches to the AST-based JS/TS detector or the regex-based Python one (Phase 16), by extension. */
function detectCapabilitiesForFile(filePath: string, content: string): DetectedCapabilities {
  return PYTHON_SOURCE_EXTENSIONS.has(path.extname(filePath))
    ? detectPythonCapabilities(content)
    : detectCapabilities(filePath, content);
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

/**
 * Reads each source file individually (not concatenated into one blob —
 * each JS/TS file is parsed as its own AST by astCapabilities.ts, and
 * treating independent files as one program would be semantically wrong.
 * Python's regex-based detectPythonCapabilities (Phase 16) doesn't
 * strictly need this — it doesn't care about file boundaries — but stays
 * on the same per-file path for one consistent merge step via
 * mergeCapabilities, rather than special-casing Python's aggregation.
 */
function readSourceFiles(
  files: string[],
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): Array<{ path: string; content: string }> {
  const results: Array<{ path: string; content: string }> = [];
  for (const file of files) {
    try {
      const stat = statSync(file);
      if (stat.size > MAX_SOURCE_FILE_BYTES) {
        skipped.push({ path: file, reason: 'source file too large to scan (>256KB)' });
        continue;
      }
      results.push({ path: file, content: readFileSync(file, 'utf8') });
      inspected.push({ path: file, kind: 'skill-source' });
    } catch (err) {
      skipped.push({ path: file, reason: `unreadable source: ${errorMessage(err)}` });
    }
  }
  return results;
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

/**
 * Strips ASCII control characters — including ANSI terminal escape
 * sequences (ESC, 0x1B) — from untrusted, manifest-derived text before it
 * enters the model. A skill's `name`/`author` come straight from its own
 * manifest, which by definition is untrusted once CHAP-SUP-001 ("skill
 * from an unverified source") exists as a check at all; those strings get
 * interpolated directly into console-reporter output with no further
 * escaping. Without this, a malicious manifest could embed terminal
 * control sequences (clear screen, hide subsequent output, etc.) in a
 * field a user is likely to actually read (see improvement_plan.md 1.11).
 * Same "sanitize once, at the trust boundary" principle configParser.ts
 * already uses for secret masking — applied here regardless of whether
 * the value came from a manifest or the directory name, since both are
 * ultimately attacker-influenced for a skill installed from an unverified
 * source.
 */
function stripControlCharacters(value: string): string {
  return (
    value
      // CSI sequences (ESC [ ... final-byte) — cursor movement, screen
      // clear, color codes, etc.
      // eslint-disable-next-line no-control-regex -- deliberately matching escape sequences to strip them
      .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '')
      // OSC sequences (ESC ] ... terminated by BEL or ESC \) — e.g.
      // terminal title changes.
      // eslint-disable-next-line no-control-regex -- deliberately matching escape sequences to strip them
      .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
      // Any remaining raw control bytes (including a lone/malformed ESC).
      // eslint-disable-next-line no-control-regex -- deliberately matching control characters to strip them
      .replace(/[\x00-\x1f\x7f]/g, '')
  );
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
  const rawAuthor =
    typeof authorField === 'string'
      ? authorField
      : isRecord(authorField) && typeof authorField['name'] === 'string'
        ? authorField['name']
        : null;
  const author = rawAuthor !== null ? stripControlCharacters(rawAuthor) : null;

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
