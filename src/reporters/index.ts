import type { Finding, Severity } from '../model/types.js';
import { formatConsoleReport, type ConsoleReportOptions } from './console.js';
import { formatGhaReport } from './gha.js';
import { formatHtmlReport } from './html.js';
import { buildScanReport, formatJsonReport } from './json.js';
import { formatMarkdownReport } from './markdown.js';
import { formatSarifReport, SARIF_SCHEMA_URI } from './sarif.js';
import type { ScanMetadata } from './types.js';

export { formatConsoleReport } from './console.js';
export type { ConsoleReportOptions } from './console.js';
export { formatGhaReport } from './gha.js';
export { formatHtmlReport } from './html.js';
export { buildScanReport, formatJsonReport } from './json.js';
export { formatMarkdownReport } from './markdown.js';
export { formatSarifReport, SARIF_SCHEMA_URI } from './sarif.js';
export { ScanReportSchema, type ScanReport } from './schema.js';
export type { ScanMetadata } from './types.js';

export const REPORT_FORMATS = ['console', 'json', 'sarif', 'markdown', 'gha', 'html'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export interface RenderReportOptions {
  console?: ConsoleReportOptions;
  /** Per-severity posture-score weight overrides (improvement_plan.md 3.4, .chaperonerc.json's scoreWeights) — applied to every format that reports a score (console/json/markdown/html; SARIF/GHA have no score concept). */
  scoreWeights?: Partial<Record<Severity, number>>;
}

/** Dispatches to the reporter for the requested format — the CLI's single entry point for turning findings into output text. */
export function renderReport(
  format: ReportFormat,
  findings: readonly Finding[],
  metadata: ScanMetadata,
  options: RenderReportOptions = {},
): string {
  switch (format) {
    case 'console':
      return formatConsoleReport(findings, metadata, {
        ...options.console,
        ...(options.scoreWeights !== undefined ? { scoreWeights: options.scoreWeights } : {}),
      });
    case 'json':
      return formatJsonReport(findings, metadata, options.scoreWeights);
    case 'sarif':
      return formatSarifReport(findings, metadata);
    case 'markdown':
      return formatMarkdownReport(findings, metadata, options.scoreWeights);
    case 'gha':
      return formatGhaReport(findings, metadata);
    case 'html':
      return formatHtmlReport(findings, metadata, options.scoreWeights);
  }
}

export interface TargetReport {
  findings: readonly Finding[];
  metadata: ScanMetadata;
}

/**
 * Aggregates several targets' findings into one report (improvement_plan.md
 * 3.2/Phase 20, `--all`) — "one aggregate report", the DoD's own chosen
 * alternative over N separate files. A single target degenerates
 * byte-for-byte to `renderReport`'s own output — no behavior change for
 * every existing single-target caller (the overwhelming majority).
 *
 * `json` aggregates as an array of the same schema-valid report objects
 * `formatJsonReport` already produces per target — still one JSON
 * document, still trivially machine-parseable. `sarif` merges each
 * target's single `runs[0]` entry into one multi-run SARIF document,
 * SARIF's own native way to represent more than one analysis pass — a
 * naive concatenation of N separate SARIF documents would not be valid
 * JSON at all. Every other format (console/markdown/html/gha) is
 * human-facing prose or line-based output, so a simple header-separated
 * concatenation is enough — no format-specific merge needed.
 */
export function renderMultiTargetReport(
  format: ReportFormat,
  targets: readonly TargetReport[],
  options: RenderReportOptions = {},
): string {
  if (targets.length === 1) {
    const [only] = targets;
    if (only === undefined) {
      return '';
    }
    return renderReport(format, only.findings, only.metadata, options);
  }

  if (format === 'json') {
    const reports = targets.map((t) =>
      buildScanReport(t.findings, t.metadata, options.scoreWeights),
    );
    return JSON.stringify(reports, null, 2);
  }

  if (format === 'sarif') {
    const runs = targets.map((t) => {
      const parsed = JSON.parse(formatSarifReport(t.findings, t.metadata)) as { runs: [unknown] };
      return parsed.runs[0];
    });
    return JSON.stringify({ $schema: SARIF_SCHEMA_URI, version: '2.1.0', runs }, null, 2);
  }

  return targets
    .map((target, index) => {
      const header = `===== Target ${String(index + 1)}/${String(targets.length)}: ${target.metadata.target} =====`;
      return `${header}\n\n${renderReport(format, target.findings, target.metadata, options)}`;
    })
    .join('\n\n');
}
