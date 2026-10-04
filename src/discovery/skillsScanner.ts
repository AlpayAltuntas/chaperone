import {
  closeSync,
  existsSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  statSync,
} from 'node:fs';
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
import { readLockfile } from './lockfiles.js';
import { PYTHON_LOCKFILES, readPythonDependencies } from './pythonDependencies.js';

const MANIFEST_FILENAMES = ['package.json', 'skill.json', 'skill.yaml', 'skill.yml'];
// JS/TS get the AST-based detectCapabilities (Phase 10); .py gets the
// regex-based detectPythonCapabilities (Phase 16, improvement_plan.md
// 1.9) — dispatched in detectCapabilitiesForFile below.
const JS_TS_SOURCE_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.jsx',
  '.ts',
  '.mts',
  '.cts',
  '.tsx',
]);
const PYTHON_SOURCE_EXTENSIONS = new Set(['.py']);
const LOCKFILE_NAMES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];
const MAX_SOURCE_FILE_BYTES = 256 * 1024;
// Files over MAX_SOURCE_FILE_BYTES get a pattern pre-pass instead of the
// AST (PROPOSED_FIXES.md 3.3), reading at most this much of each.
const MAX_PREPASS_BYTES = 16 * 1024 * 1024;
const MAX_SCAN_DEPTH = 6;

// Directories that are never skill code: dependency trees and VCS
// metadata. Every other directory, including dot-directories, is scanned,
// since skipping `.lib/` let a skill hide its payload there
// (PROPOSED_FIXES.md 3.3).
const SKIPPED_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  '.venv',
  'venv',
  '__pycache__',
]);

// Extensionless files with one of these shebang interpreters are source.
const NODE_SHEBANG = /^#!.*\b(?:node|deno|bun|tsx|ts-node)\b/;
const PYTHON_SHEBANG = /^#!.*\bpython[0-9.]*\b/;

// Patterns the large-file pre-pass treats as dynamic-code evidence.
// Minified bundles are the usual shape for an obfuscated payload, so
// skipping them outright was the worst possible blind spot.
const PREPASS_PATTERNS: ReadonlyArray<{ name: string; regex: RegExp }> = [
  { name: 'eval(', regex: /\beval\s*\(/ },
  { name: 'Function(', regex: /\bFunction\s*\(/ },
  { name: 'atob(', regex: /\batob\s*\(/ },
  { name: 'child_process', regex: /\bchild_process\b/ },
];

interface DangerousPattern {
  regex: RegExp;
  /** Only meaningful in an actual install script, not in a README's prose. */
  installScriptOnly: boolean;
}

// `(?:sudo\s+)?(?:ba|z|da)?sh\b`: a shell at a word boundary, so `| bash`,
// `| sudo sh`, and `| bash -s` match but `| shasum` doesn't.
const PIPE_TO_SHELL = String.raw`\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b`;
const DANGEROUS_INSTALL_PATTERNS: readonly DangerousPattern[] = [
  { regex: new RegExp(String.raw`curl[^\n]*${PIPE_TO_SHELL}`, 'i'), installScriptOnly: false },
  { regex: new RegExp(String.raw`wget[^\n]*${PIPE_TO_SHELL}`, 'i'), installScriptOnly: false },
  // bash <(curl ...) — process substitution instead of a pipe.
  { regex: /\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b[^\n]*/i, installScriptOnly: false },
  // PowerShell: iwr/irm ... | iex
  {
    regex:
      /\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\|\s*(?:iex|Invoke-Expression)\b/i,
    installScriptOnly: false,
  },
  // A decoded blob piped straight into a shell.
  {
    regex: new RegExp(String.raw`base64\s+(?:-d|--decode|-D)\b[^\n]*${PIPE_TO_SHELL}`, 'i'),
    installScriptOnly: false,
  },
  { regex: /\bsudo\b/i, installScriptOnly: false },
  // Installing system packages is normal README advice ("brew install
  // jq"), so these only count inside an install script.
  { regex: /\bapt-get install\b/i, installScriptOnly: true },
  { regex: /\bbrew install\b/i, installScriptOnly: true },
];

// npm lifecycle scripts that run on install. `prepare` also runs when a
// package is installed from git, which is how skills are often installed.
const NPM_INSTALL_LIFECYCLE_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];

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

  const sourceFiles = listSkillFiles(dir, skipped);
  const sourceContents = readSourceFiles(sourceFiles, inspected, skipped);
  const capabilities = mergeCapabilities(
    sourceContents.map((source) =>
      'prepass' in source
        ? source.prepass
        : detectCapabilitiesForFile(source.path, source.kind, source.content),
    ),
  );

  const packageJsonPath = manifestPath?.endsWith('package.json')
    ? manifestPath
    : findFirstExisting(dir, ['package.json']);
  const declaredDependencies = extractDependencies(
    packageJsonPath,
    manifestPath,
    manifest,
    inspected,
    skipped,
  );
  // npm wins when a skill has both; a Python skill's requirements.txt or
  // pyproject.toml is read otherwise (PROPOSED_FIXES.md 3.4).
  const python = packageJsonPath === null ? readPythonDependencies(dir) : null;
  const npmLockfile = findFirstExisting(dir, LOCKFILE_NAMES);
  if (python !== null) {
    inspected.push({ path: python.manifestPath, kind: 'skill-manifest' });
  }
  const dependencies =
    python !== null
      ? {
          ecosystem: 'pypi' as const,
          manifestPath: python.manifestPath,
          lockfilePath: python.hashPinned
            ? python.manifestPath
            : findFirstExisting(dir, PYTHON_LOCKFILES),
          names: Object.keys(python.versionsByName),
          versionsByName: python.versionsByName,
          resolved: null,
        }
      : {
          ecosystem: packageJsonPath === null ? null : ('npm' as const),
          manifestPath: packageJsonPath,
          lockfilePath: npmLockfile,
          names: Object.keys(declaredDependencies),
          versionsByName: declaredDependencies,
          resolved: npmLockfile === null ? null : readLockfile(npmLockfile),
        };
  if (
    dependencies.lockfilePath !== null &&
    dependencies.lockfilePath !== dependencies.manifestPath
  ) {
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
    launch: null,
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
 * Reads package.json's "dependencies" object (name -> version specifier
 * string) — the keys feed CHAP-SUP-006's typosquat check, the values
 * feed CHAP-SUP-003's offline vulnerability-database match
 * (improvement_plan.md 1.15/Phase 18). Reuses the already-parsed primary
 * manifest when package.json *is* that manifest; otherwise (a
 * skill.json/skill.yaml primary manifest with a separate package.json
 * alongside it) reads package.json specifically, since dependency info
 * only ever comes from that file regardless of which manifest format the
 * skill primarily uses.
 */
function extractDependencies(
  packageJsonPath: string | null,
  manifestPath: string | null,
  manifest: Record<string, unknown> | null,
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): Record<string, string> {
  if (packageJsonPath === null) {
    return {};
  }
  const packageJson =
    packageJsonPath === manifestPath ? manifest : readManifest(packageJsonPath, inspected, skipped);
  const deps =
    packageJson && isRecord(packageJson['dependencies']) ? packageJson['dependencies'] : null;
  if (!deps) {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [name, specifier] of Object.entries(deps)) {
    if (typeof specifier === 'string') {
      result[name] = specifier;
    }
  }
  return result;
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

type SourceKind = 'js' | 'python';

/** Whether a file is skill source: by extension, or by shebang for an extensionless script. */
function sourceKindFor(file: string): SourceKind | null {
  const ext = path.extname(file).toLowerCase();
  if (JS_TS_SOURCE_EXTENSIONS.has(ext)) {
    return 'js';
  }
  if (PYTHON_SOURCE_EXTENSIONS.has(ext)) {
    return 'python';
  }
  if (ext !== '') {
    return null;
  }
  const firstLine = readFirstLine(file);
  if (firstLine === null) {
    return null;
  }
  if (NODE_SHEBANG.test(firstLine)) {
    return 'js';
  }
  return PYTHON_SHEBANG.test(firstLine) ? 'python' : null;
}

function readFirstLine(file: string): string | null {
  let fd: number | null = null;
  try {
    fd = openSync(file, 'r');
    const buffer = Buffer.alloc(256);
    const bytesRead = readSync(fd, buffer, 0, buffer.length, 0);
    const text = buffer.subarray(0, bytesRead).toString('utf8');
    return text.startsWith('#!') ? (text.split('\n')[0] ?? null) : null;
  } catch {
    return null;
  } finally {
    if (fd !== null) {
      closeSync(fd);
    }
  }
}

/** Dispatches to the AST-based JS/TS detector or the regex-based Python one (Phase 16). */
function detectCapabilitiesForFile(
  filePath: string,
  kind: SourceKind,
  content: string,
): DetectedCapabilities {
  if (kind === 'python') {
    return detectPythonCapabilities(content, filePath);
  }
  // An extensionless Node script is parsed as plain JS.
  return detectCapabilities(
    path.extname(filePath) === '' ? `${filePath}.js` : filePath,
    content,
    filePath,
  );
}

/**
 * Every file in a skill directory, recursively, minus SKIPPED_DIRECTORIES.
 * A directory past MAX_SCAN_DEPTH is recorded as skipped rather than
 * silently ignored, so code nested deeper still shows in the report.
 */
function listSkillFiles(dir: string, skipped: SkippedEntry[], depth = 0): string[] {
  let entries: import('node:fs').Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }

  const files: string[] = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIPPED_DIRECTORIES.has(entry.name)) {
        continue;
      }
      if (depth >= MAX_SCAN_DEPTH) {
        skipped.push({
          path: full,
          reason: `directory too deep to scan (more than ${String(MAX_SCAN_DEPTH)} levels inside the skill)`,
        });
        continue;
      }
      files.push(...listSkillFiles(full, skipped, depth + 1));
    } else if (entry.isFile()) {
      files.push(full);
    }
  }
  return files;
}

type SourceRead =
  | { path: string; kind: SourceKind; content: string }
  | { path: string; prepass: DetectedCapabilities };

/**
 * Reads each source file individually (not concatenated into one blob —
 * each JS/TS file is parsed as its own AST by astCapabilities.ts, and
 * treating independent files as one program would be semantically wrong.
 * Python's regex-based detectPythonCapabilities (Phase 16) doesn't
 * strictly need this — it doesn't care about file boundaries — but stays
 * on the same per-file path for one consistent merge step via
 * mergeCapabilities, rather than special-casing Python's aggregation.
 *
 * A file over MAX_SOURCE_FILE_BYTES gets a pattern pre-pass instead of
 * being skipped (PROPOSED_FIXES.md 3.3), and is listed under Skipped with
 * that explanation so the reduced analysis is visible.
 */
function readSourceFiles(
  files: string[],
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): SourceRead[] {
  const results: SourceRead[] = [];
  for (const file of files) {
    const kind = sourceKindFor(file);
    if (kind === null) {
      continue;
    }
    try {
      const stat = statSync(file);
      if (stat.size > MAX_SOURCE_FILE_BYTES) {
        const hits = prepassLargeFile(file);
        skipped.push({
          path: file,
          reason:
            hits.length > 0
              ? `source file too large for full analysis (>256KB); pattern pre-pass found ${hits.join(', ')}`
              : 'source file too large for full analysis (>256KB); pattern pre-pass found nothing',
        });
        inspected.push({ path: file, kind: 'skill-source' });
        results.push({
          path: file,
          prepass: {
            shellExec: false,
            fileSystemAccess: false,
            fileSystemScoped: false,
            networkAccess: false,
            destructiveKeywords: [],
            dynamicEval: hits.length > 0,
            dataFlowToShellExec: false,
            evidence: hits.map((hit) => ({
              capability: 'dynamicEval' as const,
              file,
              line: null,
              api: `${hit} (pattern pre-pass)`,
            })),
          },
        });
        continue;
      }
      results.push({ path: file, kind, content: readFileSync(file, 'utf8') });
      inspected.push({ path: file, kind: 'skill-source' });
    } catch (err) {
      skipped.push({ path: file, reason: `unreadable source: ${errorMessage(err)}` });
    }
  }
  return results;
}

/** Names of PREPASS_PATTERNS found in the first MAX_PREPASS_BYTES of a large file. */
function prepassLargeFile(file: string): string[] {
  let fd: number | null = null;
  try {
    fd = openSync(file, 'r');
    const buffer = Buffer.alloc(Math.min(statSync(file).size, MAX_PREPASS_BYTES));
    const bytesRead = readSync(fd, buffer, 0, buffer.length, 0);
    const text = buffer.subarray(0, bytesRead).toString('utf8');
    return PREPASS_PATTERNS.filter(({ regex }) => regex.test(text)).map(({ name }) => name);
  } finally {
    if (fd !== null) {
      closeSync(fd);
    }
  }
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
    for (const key of NPM_INSTALL_LIFECYCLE_SCRIPTS) {
      const value = npmScripts[key];
      if (typeof value === 'string') {
        const matched = matchDangerousPatterns(value, true);
        if (matched.length > 0) {
          results.push({ path: `package.json#scripts.${key}`, dangerousPatterns: matched });
        }
      }
    }
  }

  // Shell scripts anywhere in the skill (`scripts/setup.sh`, not only
  // top-level), plus a top-level README, whose install instructions a
  // user is likely to copy and run.
  const shellScripts = listSkillFiles(dir, []).filter((file) => file.endsWith('.sh'));
  let readmes: string[];
  try {
    readmes = readdirSync(dir)
      .filter((entry) => /^readme/i.test(entry))
      .map((entry) => path.join(dir, entry));
  } catch {
    readmes = [];
  }

  for (const full of [...shellScripts.sort(), ...readmes.sort()]) {
    try {
      const content = readFileSync(full, 'utf8');
      inspected.push({ path: full, kind: 'skill-install-script' });
      const matched = matchDangerousPatterns(content, full.endsWith('.sh'));
      if (matched.length > 0) {
        results.push({ path: full, dangerousPatterns: matched });
      }
    } catch (err) {
      skipped.push({ path: full, reason: `unreadable install script/doc: ${errorMessage(err)}` });
    }
  }

  return { scripts: results };
}

export function matchDangerousPatterns(text: string, isInstallScript: boolean): string[] {
  const matches: string[] = [];
  for (const { regex, installScriptOnly } of DANGEROUS_INSTALL_PATTERNS) {
    if (installScriptOnly && !isInstallScript) {
      continue;
    }
    const match = regex.exec(text);
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
