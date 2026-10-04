#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as prettier from 'prettier';
import { maliciousEntriesFrom, vulnEntriesFrom, type OsvVuln } from '../src/checks/shared/osv.js';
import type { MaliciousDbEntry } from '../src/checks/shared/maliciousDb.js';
import type { VulnDbEntry } from '../src/checks/shared/vulnDb.js';
import { isMainModule } from '../src/cli.js';

// Out-of-band refresh for src/checks/shared/vulnDb.ts
// (improvement_plan.md 1.15, "real-fix half" — Phase 18). This script is
// NEVER run during `chaperone scan`, `npm test`, `npm run build`, or CI
// — it is the one deliberate place in this codebase that makes an
// outbound network call, and it exists specifically so the check itself
// never has to. A maintainer runs `npm run refresh:vulndb` by hand,
// periodically, reviews the diff like any other source change, and
// commits the regenerated file.
//
// Queries OSV.dev (https://osv.dev, the same aggregator `npm audit`
// itself draws from) for a small, curated list of npm packages —
// deliberately a snapshot, not the entire OSV database (multiple GB) —
// and keeps only the subset of each advisory's data this project's
// simple range model can represent: an exact npm-ecosystem SEMVER range
// with both an `introduced` and a `fixed` bound. An advisory using
// `last_affected` instead of `fixed`, a non-SEMVER range, or a
// vulnerability with no digits at all is skipped rather than
// approximated — see semver.ts's own doc comment for why this project
// doesn't attempt full semver-range modeling.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, '..');
const OUTPUT_PATH = path.join(REPO_ROOT, 'src', 'checks', 'shared', 'vulnDb.ts');

const MALICIOUS_OUTPUT_PATH = path.join(REPO_ROOT, 'src', 'checks', 'shared', 'maliciousDb.ts');

// Add a package name here, re-run `npm run refresh:vulndb`, review the
// diff. The packages agent skills most commonly depend on: HTTP clients,
// servers, shells, parsers, and the usual utility libraries
// (PROPOSED_FIXES.md 3.5).
export const TRACKED_PACKAGES: readonly string[] = [
  'lodash',
  'minimist',
  'axios',
  'node-fetch',
  'undici',
  'got',
  'follow-redirects',
  'request',
  'superagent',
  'ws',
  'socket.io',
  'socket.io-parser',
  'express',
  'body-parser',
  'cookie',
  'qs',
  'path-to-regexp',
  'send',
  'serve-static',
  'koa',
  'fastify',
  'jsonwebtoken',
  'jose',
  'tar',
  'tar-fs',
  'adm-zip',
  'semver',
  'shelljs',
  'execa',
  'cross-spawn',
  'simple-git',
  'puppeteer',
  'playwright',
  'cheerio',
  'jsdom',
  'marked',
  'markdown-it',
  'sanitize-html',
  'dompurify',
  'handlebars',
  'ejs',
  'pug',
  'mustache',
  'xml2js',
  'fast-xml-parser',
  'js-yaml',
  'yaml',
  'json5',
  'minimatch',
  'glob',
  'braces',
  'micromatch',
  'ip',
  'tough-cookie',
  'form-data',
  'nanoid',
  'uuid',
  'moment',
  'dayjs',
  'validator',
  'ajv',
  'crypto-js',
  'node-forge',
  'elliptic',
  'pbkdf2',
  'dotenv',
  'openai',
  '@anthropic-ai/sdk',
  'langchain',
  '@modelcontextprotocol/sdk',
  'vm2',
  'sharp',
  'multer',
  'mongoose',
  'sequelize',
  'pg',
  'mysql2',
];

// Packages that have shipped malicious versions (compromised maintainer
// accounts, protestware, injected payloads). Queried for advisories OSV
// classifies as malicious; every version listed in those advisories goes
// into maliciousDb.ts for CHAP-SUP-007 (PROPOSED_FIXES.md 3.5). The full
// OpenSSF malicious-packages feed is tens of thousands of entries, mostly
// typosquats that are malicious in every version; `--vuln-db` accepts an
// OSV export for that.
export const MALWARE_WATCHLIST: readonly string[] = [
  'event-stream',
  'flatmap-stream',
  'ua-parser-js',
  'coa',
  'rc',
  'node-ipc',
  'colors',
  'faker',
  'eslint-scope',
  'eslint-config-eslint',
  'getcookies',
  'electron-native-notify',
  'chalk',
  'debug',
  'ansi-styles',
  'ansi-regex',
  'strip-ansi',
  'supports-color',
  'wrap-ansi',
  'color-convert',
  'color-name',
  'slice-ansi',
  'is-arrayish',
  'simple-swizzle',
  'error-ex',
  'has-ansi',
  'chalk-template',
  'backslash',
  'nx',
  '@nx/devkit',
  '@nx/js',
  '@nx/workspace',
  '@ctrl/tinycolor',
  '@solana/web3.js',
  '@lottiefiles/lottie-player',
  '@rspack/core',
  '@rspack/cli',
  'vant',
  'rand-user-agent',
  'is',
  'eslint-config-prettier',
  'eslint-plugin-prettier',
  'synckit',
  '@pkgr/core',
  'napi-postinstall',
  'got-fetch',
  'web3-utils',
];

async function queryOsv(packageName: string): Promise<OsvVuln[]> {
  const response = await fetch('https://api.osv.dev/v1/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package: { name: packageName, ecosystem: 'npm' } }),
  });
  if (!response.ok) {
    throw new Error(`OSV query failed for '${packageName}': HTTP ${String(response.status)}`);
  }
  const data = (await response.json()) as { vulns?: OsvVuln[] };
  return data.vulns ?? [];
}

function renderVulnDbModule(entries: readonly VulnDbEntry[], generatedAt: string): string {
  const entryLiterals = entries
    .map(
      (e) => `  {
    packageName: ${JSON.stringify(e.packageName)},
    id: ${JSON.stringify(e.id)},
    aliases: ${JSON.stringify(e.aliases)},
    summary: ${JSON.stringify(e.summary)},
    severity: ${JSON.stringify(e.severity)},
    introduced: ${JSON.stringify(e.introduced)},
    fixed: ${JSON.stringify(e.fixed)},
  }`,
    )
    .join(',\n');

  return `// GENERATED FILE — do not hand-edit. Run \`npm run refresh:vulndb\` to
// regenerate (see scripts/refreshVulnDb.ts). Source: OSV.dev
// (https://osv.dev), queried out-of-band, never during a scan
// (improvement_plan.md 1.15/Phase 18).
//
// Tracked packages: ${String(TRACKED_PACKAGES.length)} (see TRACKED_PACKAGES in the script)

export interface VulnDbEntry {
  packageName: string;
  id: string;
  aliases: readonly string[];
  summary: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Vulnerable range lower bound (inclusive). */
  introduced: string;
  /** Vulnerable range upper bound (exclusive) — the first patched version. */
  fixed: string;
}

/** When this snapshot was taken; shown in reports so staleness is visible (PROPOSED_FIXES.md 3.5). */
export const VULN_DB_GENERATED_AT = ${JSON.stringify(generatedAt)};

/**
 * A curated offline snapshot of known npm-package vulnerabilities
 * — CHAP-SUP-003 matches a skill's dependency versions against this,
 * entirely offline. Not the whole OSV database (many GB); a scoped set
 * of packages agent skills commonly use, refreshed periodically
 * out-of-band. See DECISIONS.md, Phase 18 and PROPOSED_FIXES.md 3.5.
 */
export const VULN_DB: readonly VulnDbEntry[] = [
${entryLiterals}
];
`;
}

function renderMaliciousDbModule(
  entries: readonly MaliciousDbEntry[],
  generatedAt: string,
): string {
  const entryLiterals = entries
    .map(
      (e) => `  {
    packageName: ${JSON.stringify(e.packageName)},
    id: ${JSON.stringify(e.id)},
    summary: ${JSON.stringify(e.summary)},
    versions: ${JSON.stringify(e.versions)},
    ranges: ${JSON.stringify(e.ranges)},
  }`,
    )
    .join(',\n');
  return `// GENERATED FILE — do not hand-edit. Run \`npm run refresh:vulndb\` to
// regenerate (see scripts/refreshVulnDb.ts). Source: OSV.dev advisories
// classified as malicious, for the packages in MALWARE_WATCHLIST and
// TRACKED_PACKAGES. Generated: ${generatedAt}

export interface MaliciousDbEntry {
  packageName: string;
  id: string;
  summary: string;
  /** Exact malicious versions, or ['*'] when every version is. */
  versions: readonly string[];
  /** Malicious ranges, \`[introduced, fixed)\`; \`fixed\` null when open-ended. */
  ranges: ReadonlyArray<{ introduced: string; fixed: string | null }>;
}

/** Known-malicious package versions, matched exactly by CHAP-SUP-007 (PROPOSED_FIXES.md 3.5). */
export const MALICIOUS_DB: readonly MaliciousDbEntry[] = [
${entryLiterals}
];
`;
}

async function writeFormatted(outputPath: string, source: string): Promise<void> {
  // prettier.format() doesn't read .prettierrc.json on its own —
  // resolveConfig does that explicitly.
  const prettierConfig = await prettier.resolveConfig(outputPath);
  writeFileSync(
    outputPath,
    await prettier.format(source, { ...prettierConfig, filepath: outputPath }),
  );
}

async function main(): Promise<void> {
  const vulnEntries: VulnDbEntry[] = [];
  const maliciousEntries: MaliciousDbEntry[] = [];
  const queried = [...new Set([...TRACKED_PACKAGES, ...MALWARE_WATCHLIST])];
  for (const packageName of queried) {
    const vulns = await queryOsv(packageName);
    const malicious = maliciousEntriesFrom(vulns, packageName);
    maliciousEntries.push(...malicious);
    if (TRACKED_PACKAGES.includes(packageName)) {
      vulnEntries.push(...vulnEntriesFrom(vulns, packageName));
    }
    console.log(
      `${packageName}: ${String(vulns.length)} advisories (${String(malicious.length)} malicious)`,
    );
  }

  const generatedAt = new Date().toISOString();
  await writeFormatted(OUTPUT_PATH, renderVulnDbModule(vulnEntries, generatedAt));
  await writeFormatted(
    MALICIOUS_OUTPUT_PATH,
    renderMaliciousDbModule(maliciousEntries, generatedAt),
  );
  console.log(
    `Wrote ${path.relative(REPO_ROOT, OUTPUT_PATH)} (${String(vulnEntries.length)} advisories) and ${path.relative(REPO_ROOT, MALICIOUS_OUTPUT_PATH)} (${String(maliciousEntries.length)} malicious advisories) from ${String(queried.length)} packages.`,
  );
}

if (isMainModule(process.argv[1], import.meta.url)) {
  await main();
}
