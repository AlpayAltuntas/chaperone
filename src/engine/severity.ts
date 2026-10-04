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
// base weight per finding by severity (see computeScore for how repeats
// within one check diminish), floor at 0. `info` findings (e.g.
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

/** Bumped whenever the formula changes, so dashboards can tell scores apart (PROPOSED_FIXES.md 4.3). */
export const SCORE_VERSION = 2;

/**
 * Posture score, version 2 (PROPOSED_FIXES.md 4.3). Findings are grouped
 * by check: within a check, the most severe finding costs its full
 * weight and each further one half the previous (w, w/2, w/4, ...),
 * capped at twice the check's largest weight. One root cause repeated
 * across ten skills no longer sinks the score on its own, and fixing a
 * check's last instance still moves it. Version 1 subtracted a flat
 * weight per finding, so four criticals already scored 0.
 *
 * `weightOverrides` (improvement_plan.md 3.4, `.chaperonerc.json`'s
 * `scoreWeights`) replaces individual severity weights for this
 * computation only — `SEVERITY_SCORE_WEIGHT` itself, the default, is
 * never mutated.
 */
export function computeScore(
  findings: readonly Finding[],
  weightOverrides?: Partial<Record<Severity, number>>,
): PostureScore {
  const weights =
    weightOverrides !== undefined
      ? { ...SEVERITY_SCORE_WEIGHT, ...weightOverrides }
      : SEVERITY_SCORE_WEIGHT;
  const byCheck = new Map<string, number[]>();
  for (const finding of findings) {
    const list = byCheck.get(finding.checkId) ?? [];
    list.push(weights[finding.severity]);
    byCheck.set(finding.checkId, list);
  }
  let deduction = 0;
  for (const checkWeights of byCheck.values()) {
    const sorted = [...checkWeights].sort((a, b) => b - a);
    const largest = sorted[0] ?? 0;
    const diminished = sorted.reduce((sum, weight, i) => sum + weight / 2 ** i, 0);
    deduction += Math.min(diminished, 2 * largest);
  }
  const score = Math.max(0, Math.round(100 - deduction));
  return { score, band: scoreBand(score) };
}

function scoreBand(score: number): PostureBand {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}
