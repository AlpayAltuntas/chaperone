import type { Finding } from '../model/types.js';
import { formatConsoleReport, type ConsoleReportOptions } from './console.js';
import { formatJsonReport } from './json.js';
import { formatSarifReport } from './sarif.js';
import type { ScanMetadata } from './types.js';

export { formatConsoleReport } from './console.js';
export type { ConsoleReportOptions } from './console.js';
export { buildScanReport, formatJsonReport } from './json.js';
export { formatSarifReport } from './sarif.js';
export { ScanReportSchema, type ScanReport } from './schema.js';
export type { ScanMetadata } from './types.js';

export const REPORT_FORMATS = ['console', 'json', 'sarif'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export interface RenderReportOptions {
  console?: ConsoleReportOptions;
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
      return formatConsoleReport(findings, metadata, options.console);
    case 'json':
      return formatJsonReport(findings, metadata);
    case 'sarif':
      return formatSarifReport(findings, metadata);
  }
}
