import { compareSeverity, computeScore } from '../engine/severity.js';
import type { Finding, FindingLocation, Severity } from '../model/types.js';
import type { ScanMetadata } from './types.js';

// improvement_plan.md 3.10 — self-contained single-file HTML output, no
// external JS/CSS dependency (no CDN link, no separate stylesheet, no
// inline <script> at all: a pure static document has nothing that could
// ever produce a console error when opened — see DECISIONS.md, Phase
// 19). Everything is escaped before interpolation; a finding's message/
// location text is never raw HTML.

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#7f1d1d',
  high: '#b91c1c',
  medium: '#b45309',
  low: '#1d4ed8',
  info: '#4b5563',
};

function escapeHtml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
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

function renderFinding(finding: Finding): string {
  const location = formatLocation(finding.location);
  return `<article class="finding" style="border-left-color: ${SEVERITY_COLOR[finding.severity]}">
  <h3><span class="check-id">${escapeHtml(finding.checkId)}</span> ${escapeHtml(finding.title)}</h3>
  <p class="message">${escapeHtml(finding.message)}</p>
  ${location !== null ? `<p class="location"><strong>Location:</strong> ${escapeHtml(location)}</p>` : ''}
  <p class="owasp"><strong>OWASP:</strong> ${escapeHtml(finding.owasp)}</p>
  <p class="remediation"><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>
</article>`;
}

function renderSeverityGroup(severity: Severity, findings: readonly Finding[]): string {
  return `<section class="severity-group severity-${severity}">
  <h2 style="color: ${SEVERITY_COLOR[severity]}">${SEVERITY_LABEL[severity]} (${String(findings.length)})</h2>
  ${findings.map(renderFinding).join('\n')}
</section>`;
}

/**
 * Renders findings + scan metadata as a single, self-contained HTML
 * file — no external CSS/JS, opens correctly straight from disk with
 * `file://`. Same grouping (most severe first) and score computation
 * every other reporter shares.
 */
export function formatHtmlReport(
  findings: readonly Finding[],
  metadata: ScanMetadata,
  scoreWeights?: Partial<Record<Severity, number>>,
): string {
  const { score, band } = computeScore(findings, scoreWeights);
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }

  const sorted = [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
  const bySeverity = new Map<Severity, Finding[]>();
  for (const finding of sorted) {
    const group = bySeverity.get(finding.severity) ?? [];
    group.push(finding);
    bySeverity.set(finding.severity, group);
  }

  const findingsHtml =
    findings.length === 0
      ? '<p class="no-findings">No findings.</p>'
      : (['critical', 'high', 'medium', 'low', 'info'] as const)
          .filter((severity) => (bySeverity.get(severity) ?? []).length > 0)
          .map((severity) => renderSeverityGroup(severity, bySeverity.get(severity) ?? []))
          .join('\n');

  const skippedHtml =
    metadata.skipped.length > 0
      ? `<section class="skipped">
  <h2>Skipped (${String(metadata.skipped.length)})</h2>
  <ul>
    ${metadata.skipped.map((entry) => `<li><code>${escapeHtml(entry.path)}</code>: ${escapeHtml(entry.reason)}</li>`).join('\n')}
  </ul>
</section>`
      : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chaperone scan report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1f2937; background: #ffffff; line-height: 1.5; }
  h1 { margin-bottom: 0.25rem; }
  .meta { color: #6b7280; font-size: 0.9rem; margin-bottom: 1.5rem; }
  .summary { background: #f3f4f6; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 2rem; }
  .summary .score { font-size: 1.5rem; font-weight: 700; }
  .not-resolved { background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1.5rem; }
  .severity-group { margin-bottom: 2rem; }
  .finding { border-left: 4px solid; background: #f9fafb; border-radius: 4px; padding: 0.75rem 1rem; margin-bottom: 0.75rem; }
  .finding h3 { margin: 0 0 0.4rem; font-size: 1rem; }
  .check-id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #6b7280; font-weight: 400; }
  .finding p { margin: 0.25rem 0; font-size: 0.92rem; }
  .location code, .skipped code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .no-findings { color: #059669; font-weight: 600; }
  .skipped ul { padding-left: 1.25rem; }
  .skipped li { font-size: 0.9rem; color: #6b7280; }
</style>
</head>
<body>
<h1>Chaperone scan report</h1>
<p class="meta">Target: <code>${escapeHtml(metadata.target)}</code>${metadata.targetRootResolved ? '' : ' (not found)'}<br>
Scanned at ${escapeHtml(metadata.timestamp)} — chaperone v${escapeHtml(metadata.toolVersion)}</p>
${!metadata.targetRootResolved ? '<div class="not-resolved"><strong>Could not locate an installation to scan.</strong></div>' : ''}
<div class="summary">
  <div class="score">Posture score: ${String(score)}/100 (${band})</div>
  <div>${String(findings.length)} finding${findings.length === 1 ? '' : 's'} — ${String(counts.critical)} critical, ${String(counts.high)} high, ${String(counts.medium)} medium, ${String(counts.low)} low, ${String(counts.info)} info</div>
  <div>Inspected ${String(metadata.inspected.length)} path${metadata.inspected.length === 1 ? '' : 's'}, skipped ${String(metadata.skipped.length)}.</div>
</div>
${findingsHtml}
${skippedHtml}
</body>
</html>
`;
}
