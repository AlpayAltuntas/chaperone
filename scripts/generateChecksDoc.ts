#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as prettier from 'prettier';
import { ALL_CHECKS } from '../src/checks/index.js';
import { isMainModule } from '../src/cli.js';
import type { Check } from '../src/engine/types.js';
import type { CheckCategory } from '../src/model/types.js';

// Generates CHECKS.md's check catalog from the ALL_CHECKS registry
// (improvement_plan.md 4.2), so the code (single source of truth for
// id/title/severity/category/owasp/detects/heuristic/remediation) and
// the doc can't drift apart the way a hand-maintained copy already had
// (see every phase's commit history in DECISIONS.md). `chaperone explain
// <id>` (3.7) reads the exact same Check fields.
//
// `npm run docs:checks` regenerates and overwrites CHECKS.md.
// `npm run docs:checks:check` (wired into CI) regenerates in memory and
// fails if it doesn't match the committed file byte-for-byte.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, '..');
const CHECKS_MD_PATH = path.join(REPO_ROOT, 'CHECKS.md');

const CATEGORY_ORDER: readonly CheckCategory[] = [
  'secrets',
  'agency',
  'supply-chain',
  'injection',
  'network',
  'observability',
];

const CATEGORY_HEADING: Record<CheckCategory, string> = {
  secrets: 'Category A — Secrets & credential hygiene',
  agency: 'Category B — Excessive agency & permissions',
  'supply-chain': 'Category C — Supply chain & skill provenance',
  injection: 'Category D — Prompt-injection surface',
  network: 'Category E — Exposure & network posture',
  observability: 'Category F — Observability & recoverability',
};

const INTRO = `# Chaperone check catalog

This catalog lists every check Chaperone implements — the original set
from \`instruction.md\` §7 (v1 Phase 3), plus checks added since via
\`improvement_plan.md\`'s implementation plan. **Generated from the
\`ALL_CHECKS\` registry** (\`src/checks/index.ts\`) by \`npm run
docs:checks\` — do not hand-edit; CI (\`npm run docs:checks:check\`) fails
the build if this file is stale relative to the registry.

Run \`chaperone scan <path>\` to run every check below against an install.
\`chaperone explain <check-id>\` prints one check's full detail from the
same source this file is generated from.

## Posture score

Start at 100 and subtract a fixed weight for every finding, by severity,
then floor at 0:

| Severity | Weight |
| -------- | -----: |
| Critical | 25 |
| High | 15 |
| Medium | 7 |
| Low | 3 |
| Info | 0 |

\`info\`-severity findings (currently only ever an internal check-error
record — see \`engine/index.ts\`) never affect the score. The score maps to
a letter band:

| Score | Band |
| ------ | :--: |
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 40–59 | D |
| 0–39 | F |

Available in the JSON reporter's \`summary.score\`/\`summary.band\` (\`--format
json\`), and in the console reporter's summary line (\`— posture score
X/100 (band)\`, added in Phase 7 alongside \`--quiet\`/\`--summary-only\`).

**A note on CHAP-SUP-003:** its deliberately weak v1 heuristic (see below)
fires on essentially any skill with a \`package.json\`. It's \`Info\`
severity, not \`High\` — demoted so a signal this weak can't drag down a
genuinely hardened install's score or trip \`--fail-on high\` on its own
(see \`test/scan/fullCatalog.test.ts\`, and \`improvement_plan.md\` 1.15).

---
`;

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

// CHECKS.md has always displayed OWASP mappings with an em dash
// ("LLM06 — Sensitive Information Disclosure"); the check's own `owasp`
// field uses a colon (that's the literal string used verbatim in
// Finding.owasp across every report format — console/json/sarif). Purely
// a display transform for this doc; the underlying data is untouched.
function formatOwaspForDisplay(owasp: string): string {
  return owasp.replaceAll(': ', ' — ');
}

function renderCheck(check: Check): string {
  const severityLabel = check.severityNote ?? capitalize(check.severity);
  return [
    `### ${check.id} — ${check.title}`,
    '',
    `- **Severity:** ${severityLabel}`,
    `- **OWASP:** ${formatOwaspForDisplay(check.owasp)}`,
    `- **Detects:** ${check.detects}`,
    `- **Heuristic:** ${check.heuristic}`,
    `- **Remediation:** ${check.remediation}`,
  ].join('\n');
}

function renderCatalog(checks: readonly Check[]): string {
  const byCategory = new Map<CheckCategory, Check[]>();
  for (const check of checks) {
    const group = byCategory.get(check.category) ?? [];
    group.push(check);
    byCategory.set(check.category, group);
  }
  for (const group of byCategory.values()) {
    group.sort((a, b) => a.id.localeCompare(b.id));
  }

  const sections = CATEGORY_ORDER.filter((category) => byCategory.has(category)).map((category) => {
    const heading = `## ${CATEGORY_HEADING[category]}`;
    const checkBlocks = (byCategory.get(category) ?? []).map(renderCheck).join('\n\n');
    return `${heading}\n\n${checkBlocks}`;
  });

  return sections.join('\n\n');
}

/** Pure (no I/O beyond prettier's own formatting) — exported for tests, so a test never has to shell out or touch disk to verify the generator's output. */
export async function generateChecksDoc(checks: readonly Check[] = ALL_CHECKS): Promise<string> {
  const body = `${INTRO}\n${renderCatalog(checks)}\n`;
  return prettier.format(body, { filepath: CHECKS_MD_PATH });
}

async function main(): Promise<void> {
  const checkOnly = process.argv.includes('--check');
  const generated = await generateChecksDoc();

  if (checkOnly) {
    const committed = readFileSync(CHECKS_MD_PATH, 'utf8');
    if (committed !== generated) {
      console.error(
        'CHECKS.md is stale relative to the ALL_CHECKS registry. Run `npm run docs:checks` and commit the result.',
      );
      process.exitCode = 1;
      return;
    }
    console.log('CHECKS.md is up to date with the ALL_CHECKS registry.');
    return;
  }

  writeFileSync(CHECKS_MD_PATH, generated);
  console.log(
    `Wrote ${path.relative(REPO_ROOT, CHECKS_MD_PATH)} from ${String(ALL_CHECKS.length)} checks.`,
  );
}

if (isMainModule(process.argv[1], import.meta.url)) {
  await main();
}
