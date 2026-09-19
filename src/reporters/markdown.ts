import { compareSeverity, computeScore } from '../engine/severity.js';
import type { Finding, FindingLocation, Severity } from '../model/types.js';
import type { ScanMetadata } from './types.js';

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

/**
 * Renders findings + scan metadata as a single Markdown table — cheaper
 * to build than a full HTML reporter and directly useful for the CI use
 * case the README already documents (post as a PR comment via
 * `gh pr comment`, improvement_plan.md 3.9). Findings are sorted most
 * severe first, same order the console reporter groups by.
 */
export function formatMarkdownReport(findings: readonly Finding[], metadata: ScanMetadata): string {
  const lines: string[] = [];

  lines.push('# Chaperone scan report', '');
  lines.push(
    `**Target:** \`${metadata.target}\`${metadata.targetRootResolved ? '' : ' (not found)'}`,
  );
  lines.push(`**Scanned at:** ${metadata.timestamp} — chaperone v${metadata.toolVersion}`, '');

  if (!metadata.targetRootResolved) {
    lines.push('> **Could not locate an installation to scan.**', '');
  } else if (findings.length === 0) {
    lines.push('No findings.', '');
  } else {
    const sorted = [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
    lines.push('| Severity | Check | Message | Location |');
    lines.push('| --- | --- | --- | --- |');
    for (const finding of sorted) {
      lines.push(
        `| ${SEVERITY_LABEL[finding.severity]} | \`${finding.checkId}\` | ${escapeCell(finding.message)} | ${escapeCell(formatLocation(finding.location) ?? '—')} |`,
      );
    }
    lines.push('');
  }

  if (metadata.skipped.length > 0) {
    lines.push(`**Skipped (${String(metadata.skipped.length)}):**`, '');
    for (const entry of metadata.skipped) {
      lines.push(`- \`${entry.path}\`: ${entry.reason}`);
    }
    lines.push('');
  }

  lines.push(formatSummary(findings, metadata));

  return lines.join('\n');
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

// A Markdown table cell can't contain a literal pipe or newline without
// breaking the table structure — escape/replace them. Finding text is
// Chaperone's own generated prose (never raw file content — secrets are
// already masked upstream), but a scanned skill/file name could still
// legitimately contain either character.
function escapeCell(text: string): string {
  return text.replaceAll('|', '\\|').replaceAll('\n', ' ');
}

function formatSummary(findings: readonly Finding[], metadata: ScanMetadata): string {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  const { score, band } = computeScore(findings);
  const countLine =
    `**Summary:** ${String(findings.length)} finding${findings.length === 1 ? '' : 's'} ` +
    `(${String(counts.critical)} critical, ${String(counts.high)} high, ${String(counts.medium)} medium, ` +
    `${String(counts.low)} low, ${String(counts.info)} info) — posture score ${String(score)}/100 (${band})`;
  const inspectedCount = metadata.inspected.length;
  const skippedCount = metadata.skipped.length;
  const inspectedLine = `Inspected ${String(inspectedCount)} path${inspectedCount === 1 ? '' : 's'}, skipped ${String(skippedCount)}.`;
  return `${countLine}\n${inspectedLine}`;
}
