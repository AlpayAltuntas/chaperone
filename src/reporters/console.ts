import pc from 'picocolors';
import { compareSeverity, SEVERITY_ORDER } from '../engine/severity.js';
import type { Finding, FindingLocation, Severity } from '../model/types.js';
import type { ScanMetadata } from './types.js';

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

const SEVERITY_COLOR: Record<Severity, (text: string) => string> = {
  critical: (text) => pc.bold(pc.red(text)),
  high: (text) => pc.red(text),
  medium: (text) => pc.yellow(text),
  low: (text) => pc.cyan(text),
  info: (text) => pc.gray(text),
};

/**
 * Renders findings + scan metadata as human-readable console text, grouped
 * by severity (critical first). Colors come from picocolors, which
 * auto-disables itself on a non-TTY stream or when NO_COLOR is set, so this
 * degrades to plain text without any extra flag handling here.
 */
export function formatConsoleReport(findings: readonly Finding[], metadata: ScanMetadata): string {
  const lines: string[] = [];

  lines.push(pc.bold('Chaperone scan report'));
  lines.push(`Target: ${metadata.target}${metadata.targetRootResolved ? '' : ' (not found)'}`);
  lines.push(`Scanned at ${metadata.timestamp} — chaperone v${metadata.toolVersion}`);
  lines.push('');

  if (findings.length === 0) {
    lines.push(pc.green('No findings.'));
  } else {
    const grouped = groupBySeverity(findings);
    for (const severity of SEVERITY_ORDER) {
      const group = grouped.get(severity);
      if (group === undefined || group.length === 0) {
        continue;
      }
      const color = SEVERITY_COLOR[severity];
      lines.push(color(`${SEVERITY_LABEL[severity]} (${group.length})`));
      lines.push('');
      for (const finding of group) {
        lines.push(...formatFinding(finding));
      }
    }
  }

  lines.push(formatSummary(findings, metadata));

  return lines.join('\n');
}

function formatFinding(finding: Finding): string[] {
  const lines = [`  [${finding.checkId}] ${finding.title}`, `    ${finding.message}`];
  const location = formatLocation(finding.location);
  if (location !== null) {
    lines.push(`    Location: ${location}`);
  }
  lines.push(`    OWASP: ${finding.owasp}`);
  lines.push(`    Remediation: ${finding.remediation}`);
  lines.push('');
  return lines;
}

function formatLocation(location: FindingLocation): string | null {
  const parts: string[] = [];
  if (location.filePath !== null) {
    parts.push(
      location.line !== null ? `${location.filePath}:${String(location.line)}` : location.filePath,
    );
  }
  if (location.detail !== null) {
    parts.push(`(${location.detail})`);
  }
  return parts.length > 0 ? parts.join(' ') : null;
}

function groupBySeverity(findings: readonly Finding[]): Map<Severity, Finding[]> {
  const sorted = [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
  const map = new Map<Severity, Finding[]>();
  for (const finding of sorted) {
    const group = map.get(finding.severity) ?? [];
    group.push(finding);
    map.set(finding.severity, group);
  }
  return map;
}

function formatSummary(findings: readonly Finding[], metadata: ScanMetadata): string {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  const countLine =
    `Summary: ${String(findings.length)} finding${findings.length === 1 ? '' : 's'} ` +
    `(${String(counts.critical)} critical, ${String(counts.high)} high, ${String(counts.medium)} medium, ` +
    `${String(counts.low)} low, ${String(counts.info)} info)`;
  const inspectedLine = `Inspected ${String(metadata.inspectedCount)} path${metadata.inspectedCount === 1 ? '' : 's'}, skipped ${String(metadata.skippedCount)}.`;
  return `${countLine}\n${inspectedLine}`;
}
