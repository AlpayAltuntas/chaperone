#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { MALICIOUS_DB, type MaliciousDbEntry } from '../src/checks/shared/maliciousDb.js';
import { VULN_DB, VULN_DB_GENERATED_AT, type VulnDbEntry } from '../src/checks/shared/vulnDb.js';
import { isMainModule } from '../src/cli.js';

// Summarizes what a data refresh changed, for the PR the scheduled
// refresh workflow opens (roadmap R6.1). Run once before
// `npm run refresh:vulndb` to snapshot the bundled data, and once after
// to compare:
//
//   tsx scripts/vulnDbDelta.ts --snapshot before.json
//   npm run refresh:vulndb
//   tsx scripts/vulnDbDelta.ts --changed before.json   # exit 0 if the data changed, 3 if not
//   tsx scripts/vulnDbDelta.ts --compare before.json > summary.md
//
// The comparison runs in a fresh process, so it sees the regenerated
// modules, not the ones imported before the refresh.

export interface AdvisorySnapshot {
  generatedAt: string;
  vulns: readonly VulnDbEntry[];
  malicious: readonly MaliciousDbEntry[];
}

export interface AdvisoryDelta {
  generatedBefore: string;
  generatedAfter: string;
  vulnsBefore: number;
  vulnsAfter: number;
  maliciousBefore: number;
  maliciousAfter: number;
  /** Per package, advisory counts that changed (vulnerabilities and malware combined). */
  packageChanges: Array<{ packageName: string; before: number; after: number }>;
  addedMalicious: MaliciousDbEntry[];
  removedMalicious: MaliciousDbEntry[];
  /**
   * New malicious entries claiming that every version of a package is
   * malicious. Right for a package that was malware from the start, but a
   * misclassified advisory here would flag every user of a legitimate
   * package as critical, so each one needs a human look.
   */
  broadMalicious: MaliciousDbEntry[];
}

const entryKey = (entry: { packageName: string; id: string }): string =>
  `${entry.packageName}\u0000${entry.id}`;

/** True when a malicious entry covers every version of its package. */
export function coversEveryVersion(entry: MaliciousDbEntry): boolean {
  return (
    entry.versions.includes('*') ||
    entry.ranges.some((range) => range.introduced === '0' && range.fixed === null)
  );
}

function countByPackage(snapshot: AdvisorySnapshot): Map<string, number> {
  const counts = new Map<string, number>();
  for (const entry of [...snapshot.vulns, ...snapshot.malicious]) {
    counts.set(entry.packageName, (counts.get(entry.packageName) ?? 0) + 1);
  }
  return counts;
}

/** Compares two advisory snapshots. Pure, so the PR summary logic is unit-tested. */
export function diffAdvisoryData(before: AdvisorySnapshot, after: AdvisorySnapshot): AdvisoryDelta {
  const beforeCounts = countByPackage(before);
  const afterCounts = countByPackage(after);
  const packageChanges = [...new Set([...beforeCounts.keys(), ...afterCounts.keys()])]
    .map((packageName) => ({
      packageName,
      before: beforeCounts.get(packageName) ?? 0,
      after: afterCounts.get(packageName) ?? 0,
    }))
    .filter((change) => change.before !== change.after)
    .sort((a, b) => a.packageName.localeCompare(b.packageName));

  const beforeMalicious = new Set(before.malicious.map(entryKey));
  const afterMalicious = new Set(after.malicious.map(entryKey));
  const addedMalicious = after.malicious.filter((entry) => !beforeMalicious.has(entryKey(entry)));
  const removedMalicious = before.malicious.filter((entry) => !afterMalicious.has(entryKey(entry)));

  return {
    generatedBefore: before.generatedAt,
    generatedAfter: after.generatedAt,
    vulnsBefore: before.vulns.length,
    vulnsAfter: after.vulns.length,
    maliciousBefore: before.malicious.length,
    maliciousAfter: after.malicious.length,
    packageChanges,
    addedMalicious,
    removedMalicious,
    broadMalicious: addedMalicious.filter(coversEveryVersion),
  };
}

/**
 * Whether the advisory data itself changed. Ignores the snapshot
 * timestamp, which the refresh rewrites on every run, so a month with no
 * new advisories doesn't open a PR.
 */
export function hasDataChanges(before: AdvisorySnapshot, after: AdvisorySnapshot): boolean {
  return (
    JSON.stringify([before.vulns, before.malicious]) !==
    JSON.stringify([after.vulns, after.malicious])
  );
}

function describeAffected(entry: MaliciousDbEntry): string {
  const parts = [
    ...entry.versions,
    ...entry.ranges.map(
      (range) => `>=${range.introduced}${range.fixed === null ? '' : ` <${range.fixed}`}`,
    ),
  ];
  return parts.length === 0 ? '(no versions listed)' : parts.join(', ');
}

/** Escapes text for a Markdown table cell (advisory summaries are third-party text). */
function cell(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

const signed = (n: number): string => (n > 0 ? `+${String(n)}` : String(n));

/** The PR body: counts, per-package changes, new malware, and the review checklist. */
export function formatDeltaMarkdown(delta: AdvisoryDelta): string {
  const lines: string[] = [
    '## Advisory data refresh',
    '',
    `Snapshot ${delta.generatedBefore} → ${delta.generatedAfter}, from OSV.dev.`,
    '',
    '| Data | Before | After | Change |',
    '| --- | ---: | ---: | ---: |',
    `| Vulnerability advisories | ${String(delta.vulnsBefore)} | ${String(delta.vulnsAfter)} | ${signed(delta.vulnsAfter - delta.vulnsBefore)} |`,
    `| Known-malicious entries | ${String(delta.maliciousBefore)} | ${String(delta.maliciousAfter)} | ${signed(delta.maliciousAfter - delta.maliciousBefore)} |`,
    '',
  ];

  if (delta.broadMalicious.length > 0) {
    lines.push(
      '> [!WARNING]',
      '> These new entries mark **every version** of a package as malicious. That is right only',
      '> for a package that was malware from the start; for a legitimate package it would flag',
      '> every user as critical. Check each advisory before merging.',
      '',
      ...delta.broadMalicious.map(
        (entry) => `- \`${entry.packageName}\`: ${entry.id} (${cell(entry.summary)})`,
      ),
      '',
    );
  }

  lines.push('### New known-malicious entries', '');
  if (delta.addedMalicious.length === 0) {
    lines.push('None.', '');
  } else {
    lines.push('| Package | Advisory | Affected | Summary |', '| --- | --- | --- | --- |');
    for (const entry of delta.addedMalicious) {
      lines.push(
        `| \`${entry.packageName}\` | ${entry.id} | ${cell(describeAffected(entry))} | ${cell(entry.summary)} |`,
      );
    }
    lines.push('');
  }

  if (delta.removedMalicious.length > 0) {
    lines.push(
      '### Removed known-malicious entries',
      '',
      ...delta.removedMalicious.map((entry) => `- \`${entry.packageName}\`: ${entry.id}`),
      '',
    );
  }

  lines.push('### Advisory counts by package', '');
  if (delta.packageChanges.length === 0) {
    lines.push('No package changed.', '');
  } else {
    lines.push('| Package | Before | After |', '| --- | ---: | ---: |');
    for (const change of delta.packageChanges) {
      lines.push(
        `| \`${change.packageName}\` | ${String(change.before)} | ${String(change.after)} |`,
      );
    }
    lines.push('');
  }

  lines.push(
    '### Review checklist',
    '',
    '- [ ] Every entry under the warning above (if any) is a package that was malicious from the start',
    '- [ ] New known-malicious entries match real compromises (open each advisory)',
    '- [ ] No legitimate package lost or gained advisories unexpectedly',
    '- [ ] CI is green on this PR',
    '',
    'This PR was opened by the scheduled data refresh. Never auto-merge it.',
  );
  return `${lines.join('\n')}\n`;
}

function currentSnapshot(): AdvisorySnapshot {
  return { generatedAt: VULN_DB_GENERATED_AT, vulns: VULN_DB, malicious: MALICIOUS_DB };
}

function main(argv: readonly string[]): void {
  const [mode, file] = argv;
  if (mode === '--snapshot' && file !== undefined) {
    writeFileSync(file, `${JSON.stringify(currentSnapshot())}\n`);
    return;
  }
  if (mode === '--changed' && file !== undefined) {
    const before = JSON.parse(readFileSync(file, 'utf8')) as AdvisorySnapshot;
    process.exitCode = hasDataChanges(before, currentSnapshot()) ? 0 : 3;
    return;
  }
  if (mode === '--compare' && file !== undefined) {
    const before = JSON.parse(readFileSync(file, 'utf8')) as AdvisorySnapshot;
    process.stdout.write(formatDeltaMarkdown(diffAdvisoryData(before, currentSnapshot())));
    return;
  }
  console.error('usage: vulnDbDelta.ts --snapshot <file> | --changed <file> | --compare <file>');
  process.exitCode = 2;
}

if (isMainModule(process.argv[1], import.meta.url)) {
  main(process.argv.slice(2));
}
