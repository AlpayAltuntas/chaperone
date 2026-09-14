import type { Finding, Severity } from '../model/types.js';

// Most severe first — reporters group/sort by this order.
export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank(a) - severityRank(b);
}

/** True when `severity` is at least as severe as `threshold` (e.g. for --fail-on). */
export function severityMeetsThreshold(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) <= severityRank(threshold);
}

// Posture score formula (documented in CHECKS.md): start at 100, subtract a
// fixed weight per finding by severity, floor at 0. `info` findings (e.g.
// an internal check-error record) never affect the score.
export const SEVERITY_SCORE_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 7,
  low: 3,
  info: 0,
};

export type PostureBand = 'A' | 'B' | 'C' | 'D' | 'F';

export interface PostureScore {
  score: number;
  band: PostureBand;
}

export function computeScore(findings: readonly Finding[]): PostureScore {
  const deduction = findings.reduce(
    (sum, finding) => sum + SEVERITY_SCORE_WEIGHT[finding.severity],
    0,
  );
  const score = Math.max(0, 100 - deduction);
  return { score, band: scoreBand(score) };
}

function scoreBand(score: number): PostureBand {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}
