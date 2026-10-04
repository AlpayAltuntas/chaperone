import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
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
export function loadBaseline(baselinePath: string): ScanReport {
  if (!existsSync(baselinePath)) {
    throw new Error(`baseline file not found: ${baselinePath}`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(baselinePath, 'utf8'));
  } catch (err) {
    throw new Error(`could not parse ${baselinePath} as JSON: ${errorMessage(err)}`, {
      cause: err,
    });
  }

  const result = ScanReportSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
    throw new Error(`invalid baseline file ${baselinePath}: ${issues}`);
  }
  return result.data;
}

/**
 * Identifies "the same finding" across two scans, as
 * `checkId` + file path relative to the scan target + `detail`.
 *
 * - `location.line` is excluded: unrelated edits shifting lines elsewhere
 *   in a file would otherwise make an unchanged finding look new.
 * - `message` is excluded: wording changes between Chaperone releases,
 *   and some messages embed variable data, would otherwise resurface
 *   every finding after an upgrade.
 * - The file path is made relative to `targetRoot` when it lies inside
 *   it, so a baseline captured at `/Users/me/clawd` still matches a scan
 *   of the same install at `/home/runner/work/clawd`. A path outside the
 *   target stays absolute rather than becoming a `../..` chain.
 *
 * Before PROPOSED_FIXES.md 2.7 this used the absolute path and the
 * message, so moving an install made every finding "new". Old (v0.2)
 * baselines still match: their `target` field is the absolute root their
 * paths are relative to.
 */
export function findingFingerprint(finding: Finding, targetRoot: string): string {
  return JSON.stringify([
    finding.checkId,
    relativeToTarget(finding.location.filePath, targetRoot),
    finding.location.detail,
  ]);
}

/** `filePath` relative to `targetRoot` with `/` separators, or unchanged when it isn't inside it. */
export function relativeToTarget(filePath: string | null, targetRoot: string): string | null {
  if (filePath === null || !path.isAbsolute(filePath) || !path.isAbsolute(targetRoot)) {
    return filePath;
  }
  const relative = path.relative(targetRoot, filePath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    return filePath;
  }
  return relative.split(path.sep).join('/');
}

/** The findings in `findings` (scanned at `targetRoot`) that aren't in `baseline` (scanned at `baseline.target`). */
export function findNewFindings(
  findings: readonly Finding[],
  baseline: ScanReport,
  targetRoot: string,
): Finding[] {
  const baselineFingerprints = new Set(
    baseline.findings.map((finding) => findingFingerprint(finding, baseline.target)),
  );
  return findings.filter(
    (finding) => !baselineFingerprints.has(findingFingerprint(finding, targetRoot)),
  );
}
