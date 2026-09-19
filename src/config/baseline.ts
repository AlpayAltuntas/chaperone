import { existsSync, readFileSync } from 'node:fs';
import { errorMessage } from '../discovery/errors.js';
import type { Finding } from '../model/types.js';
import { ScanReportSchema, type ScanReport } from '../reporters/schema.js';

// Baseline/diff mode (improvement_plan.md 3.5) — a saved Chaperone JSON
// report (ScanReportSchema; the schema already supports this for free,
// per the plan's own note) read back in to filter a later scan down to
// only what's new since it was captured. Lets a team adopt Chaperone on
// an existing, imperfect install and gate CI on new findings only,
// without either fixing everything on day one or disabling --fail-on.

/**
 * Loads and validates a baseline file. An explicit `--baseline <file>`
 * must exist and parse/validate — silently ignoring a typo'd path would
 * be worse than failing loudly, matching how `--config`
 * (chaperoneConfig.ts) and `--output` already fail on a bad path.
 * There is deliberately no default-file auto-discovery here (unlike
 * `.chaperonerc.json`) — the plan only ever describes an explicit
 * `--baseline <file>`, and a silently-picked-up stale baseline would be
 * a much easier mistake to make unnoticed than a missing suppression
 * config.
 */
export function loadBaseline(path: string): ScanReport {
  if (!existsSync(path)) {
    throw new Error(`baseline file not found: ${path}`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`could not parse ${path} as JSON: ${errorMessage(err)}`, { cause: err });
  }

  const result = ScanReportSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
    throw new Error(`invalid baseline file ${path}: ${issues}`);
  }
  return result.data;
}

/**
 * Identifies "the same finding" across two scans. Deliberately excludes
 * `location.line`: unrelated edits shifting line numbers elsewhere in a
 * file would otherwise make an unchanged finding look "new" on every
 * diff. `checkId` + `filePath` + `detail` + `message` is what's left —
 * specific enough that two genuinely different findings essentially
 * never collide, without being so specific that harmless line drift
 * defeats the whole point of a baseline.
 */
export function findingFingerprint(finding: Finding): string {
  return JSON.stringify([
    finding.checkId,
    finding.location.filePath,
    finding.location.detail,
    finding.message,
  ]);
}

/** Findings present in `findings` but not in `baseline` — i.e. new since the baseline was captured. */
export function findNewFindings(findings: readonly Finding[], baseline: ScanReport): Finding[] {
  const baselineFingerprints = new Set(baseline.findings.map(findingFingerprint));
  return findings.filter((finding) => !baselineFingerprints.has(findingFingerprint(finding)));
}
