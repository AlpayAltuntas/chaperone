import { computeScore } from '../engine/severity.js';
import type { Finding, Severity } from '../model/types.js';
import type { ScanMetadata } from './types.js';

/**
 * The posture-score phrase for the human-facing summary lines. A scan
 * that never located an installation has no score: an empty finding
 * list would otherwise read as 100/100 (A), the exact "nothing scanned
 * looks like nothing found" confusion PROPOSED_FIXES.md 2.1 removes.
 */
export function formatScoreLabel(
  findings: readonly Finding[],
  metadata: ScanMetadata,
  scoreWeights?: Partial<Record<Severity, number>>,
): string {
  if (!metadata.targetRootResolved) {
    return 'no posture score (nothing scanned)';
  }
  const { score, band } = computeScore(findings, scoreWeights);
  return `posture score ${String(score)}/100 (${band})`;
}
