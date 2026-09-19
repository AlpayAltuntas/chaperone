import type { Finding, Severity } from '../model/types.js';
import type { ScanMetadata } from './types.js';

// GitHub Actions workflow commands only define these three annotation
// levels (https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions).
type GhaAnnotationLevel = 'error' | 'warning' | 'notice';

const SEVERITY_TO_GHA_LEVEL: Record<Severity, GhaAnnotationLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'notice',
  info: 'notice',
};

/**
 * Renders findings as GitHub Actions `::error file=...::`/`::warning::`/
 * `::notice::` workflow commands (improvement_plan.md 3.9) — inline PR
 * annotations without the full SARIF code-scanning upload flow. Printed
 * to a step's stdout, GitHub parses these live and attaches them to the
 * relevant file/line in a PR diff (or the job log, when there's no
 * location). Complements the SARIF reporter rather than replacing it —
 * SARIF is for the code-scanning tab, this is for immediate inline
 * annotations with zero extra CI steps.
 */
export function formatGhaReport(findings: readonly Finding[], metadata: ScanMetadata): string {
  if (!metadata.targetRootResolved) {
    return '::error::Could not locate an installation to scan.';
  }

  const lines = findings.map(formatAnnotation);
  lines.push(
    `::notice::Chaperone scan: ${String(findings.length)} finding${findings.length === 1 ? '' : 's'} found.`,
  );
  return lines.join('\n');
}

function formatAnnotation(finding: Finding): string {
  const level = SEVERITY_TO_GHA_LEVEL[finding.severity];
  const properties: string[] = [];
  if (finding.location.filePath !== null) {
    properties.push(`file=${escapeProperty(finding.location.filePath)}`);
  }
  if (finding.location.line !== null) {
    properties.push(`line=${String(finding.location.line)}`);
  }
  properties.push(`title=${escapeProperty(`${finding.checkId}: ${finding.title}`)}`);

  const propertyString = properties.length > 0 ? ` ${properties.join(',')}` : '';
  return `::${level}${propertyString}::${escapeData(finding.message)}`;
}

// GitHub's documented escaping for workflow command data (message text):
// https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#escaping-data
function escapeData(text: string): string {
  return text.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
}

// Property *values* need two extra characters escaped beyond escapeData
// (`:` and `,`), since those are the property-list delimiters.
function escapeProperty(text: string): string {
  return escapeData(text).replaceAll(':', '%3A').replaceAll(',', '%2C');
}
