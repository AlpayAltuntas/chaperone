#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as prettier from 'prettier';
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

// Add a package name here, re-run `npm run refresh:vulndb`, review the
// diff. Kept small and deliberate.
const TRACKED_PACKAGES: readonly string[] = ['lodash', 'minimist'];

interface OsvPackage {
  name: string;
  ecosystem: string;
}

interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

interface OsvRange {
  type: string;
  events: OsvRangeEvent[];
}

interface OsvAffected {
  package?: OsvPackage;
  ranges?: OsvRange[];
}

interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  affected?: OsvAffected[];
}

export interface VulnDbEntry {
  packageName: string;
  id: string;
  aliases: readonly string[];
  summary: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  introduced: string;
  fixed: string;
}

function normalizeSeverity(osvSeverity: string | undefined): VulnDbEntry['severity'] | null {
  switch ((osvSeverity ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return null;
  }
}

/** Extracts this project's simplified {introduced, fixed} shape from one OSV `affected` entry for the exact tracked package, or null if it doesn't fit that shape. */
function extractSimpleRange(
  affected: OsvAffected,
  packageName: string,
): { introduced: string; fixed: string } | null {
  if (affected.package?.ecosystem !== 'npm' || affected.package.name !== packageName) {
    return null;
  }
  for (const range of affected.ranges ?? []) {
    if (range.type !== 'SEMVER') {
      continue;
    }
    const introducedEvent = range.events.find((e) => e.introduced !== undefined);
    const fixedEvent = range.events.find((e) => e.fixed !== undefined);
    if (introducedEvent?.introduced !== undefined && fixedEvent?.fixed !== undefined) {
      return { introduced: introducedEvent.introduced, fixed: fixedEvent.fixed };
    }
  }
  return null;
}

async function fetchAdvisoriesForPackage(packageName: string): Promise<VulnDbEntry[]> {
  const response = await fetch('https://api.osv.dev/v1/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package: { name: packageName, ecosystem: 'npm' } }),
  });
  if (!response.ok) {
    throw new Error(`OSV query failed for '${packageName}': HTTP ${String(response.status)}`);
  }
  const data = (await response.json()) as { vulns?: OsvVuln[] };

  const entries: VulnDbEntry[] = [];
  for (const vuln of data.vulns ?? []) {
    const severity = normalizeSeverity(vuln.database_specific?.severity);
    if (severity === null) {
      continue;
    }
    for (const affected of vuln.affected ?? []) {
      const range = extractSimpleRange(affected, packageName);
      if (range === null) {
        continue;
      }
      entries.push({
        packageName,
        id: vuln.id,
        aliases: vuln.aliases ?? [],
        summary: vuln.summary ?? vuln.id,
        severity,
        introduced: range.introduced,
        fixed: range.fixed,
      });
      break; // one entry per vuln per package is enough signal
    }
  }
  return entries;
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
// Generated: ${generatedAt}
// Tracked packages: ${TRACKED_PACKAGES.join(', ')}

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

/**
 * A small, curated offline snapshot of known npm-package vulnerabilities
 * — CHAP-SUP-003 matches a skill's declared dependency versions against
 * this, entirely offline. Not the whole OSV database (many GB); a
 * deliberately scoped set of well-known packages, refreshed periodically
 * out-of-band. See DECISIONS.md, Phase 18.
 */
export const VULN_DB: readonly VulnDbEntry[] = [
${entryLiterals}
];
`;
}

async function main(): Promise<void> {
  const allEntries: VulnDbEntry[] = [];
  for (const packageName of TRACKED_PACKAGES) {
    const entries = await fetchAdvisoriesForPackage(packageName);
    allEntries.push(...entries);
    console.log(
      `${packageName}: ${String(entries.length)} advisor${entries.length === 1 ? 'y' : 'ies'}`,
    );
  }

  const generatedAt = new Date().toISOString();
  // prettier.format() doesn't read .prettierrc.json on its own —
  // resolveConfig does that explicitly (same reason CHECKS.md's
  // generator never needed this: markdown has no quote-style setting
  // for it to silently default away from).
  const prettierConfig = await prettier.resolveConfig(OUTPUT_PATH);
  const formatted = await prettier.format(renderVulnDbModule(allEntries, generatedAt), {
    ...prettierConfig,
    filepath: OUTPUT_PATH,
  });
  writeFileSync(OUTPUT_PATH, formatted);
  console.log(
    `Wrote ${path.relative(REPO_ROOT, OUTPUT_PATH)} — ${String(allEntries.length)} total advisories for ${String(TRACKED_PACKAGES.length)} packages.`,
  );
}

if (isMainModule(process.argv[1], import.meta.url)) {
  await main();
}
