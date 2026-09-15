import { computeScore } from '../engine/severity.js';
import type { Finding, Severity } from '../model/types.js';
import { ScanReportSchema, type ScanReport } from './schema.js';
import type { ScanMetadata } from './types.js';

export function buildScanReport(findings: readonly Finding[], metadata: ScanMetadata): ScanReport {
  const { score, band } = computeScore(findings);
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
  }

  return {
    tool: { name: 'chaperone', version: metadata.toolVersion },
    target: metadata.target,
    targetRootResolved: metadata.targetRootResolved,
    timestamp: metadata.timestamp,
    summary: { totalFindings: findings.length, bySeverity, score, band },
    findings: [...findings],
    inspected: [...metadata.inspected],
    skipped: [...metadata.skipped],
  };
}

/** Renders findings + scan metadata as the schema-validated JSON report (see reporters/schema.ts). */
export function formatJsonReport(findings: readonly Finding[], metadata: ScanMetadata): string {
  const report = ScanReportSchema.parse(buildScanReport(findings, metadata));
  return JSON.stringify(report, null, 2);
}
