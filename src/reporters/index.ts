import type { Finding, Severity } from '../model/types.js';
import { formatConsoleReport, type ConsoleReportOptions } from './console.js';
import { formatGhaReport } from './gha.js';
import { formatJsonReport } from './json.js';
import { formatMarkdownReport } from './markdown.js';
import { formatSarifReport } from './sarif.js';
import type { ScanMetadata } from './types.js';

export { formatConsoleReport } from './console.js';
export type { ConsoleReportOptions } from './console.js';
export { formatGhaReport } from './gha.js';
export { buildScanReport, formatJsonReport } from './json.js';
export { formatMarkdownReport } from './markdown.js';
export { formatSarifReport } from './sarif.js';
export { ScanReportSchema, type ScanReport } from './schema.js';
export type { ScanMetadata } from './types.js';

export const REPORT_FORMATS = ['console', 'json', 'sarif', 'markdown', 'gha'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export interface RenderReportOptions {
  console?: ConsoleReportOptions;
  /** Per-severity posture-score weight overrides (improvement_plan.md 3.4, .chaperonerc.json's scoreWeights) — applied to every format that reports a score (console/json/markdown; SARIF has no score concept). */
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
  }
}
