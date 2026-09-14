#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { Command, InvalidArgumentError } from 'commander';
import { ALL_CHECKS } from './checks/index.js';
import { discoverAgent } from './discovery/index.js';
import { runChecks } from './engine/index.js';
import { SEVERITY_ORDER, severityMeetsThreshold } from './engine/severity.js';
import type { Severity } from './model/types.js';
import { REPORT_FORMATS, renderReport, type ReportFormat } from './reporters/index.js';
import type { ScanMetadata } from './reporters/types.js';
import { VERSION } from './version.js';

interface ScanCommandOptions {
  format: ReportFormat;
  failOn: Severity;
  output?: string;
}

function parseFormat(value: string): ReportFormat {
  if (!(REPORT_FORMATS as readonly string[]).includes(value)) {
    throw new InvalidArgumentError(`must be one of: ${REPORT_FORMATS.join(', ')}`);
  }
  return value as ReportFormat;
}

function parseSeverity(value: string): Severity {
  if (!(SEVERITY_ORDER as readonly string[]).includes(value)) {
    throw new InvalidArgumentError(`must be one of: ${SEVERITY_ORDER.join(', ')}`);
  }
  return value as Severity;
}

export function buildProgram(): Command {
  const program = new Command();

  program
    .name('chaperone')
    .description(
      'Security scanner that audits self-hosted personal AI agents for OWASP-LLM-mapped security weaknesses.',
    )
    .version(VERSION);

  program
    .command('scan')
    .argument(
      '[path]',
      'agent root/config directory to scan (probes known default locations if omitted)',
    )
    .description('Scan an agent installation and report security findings')
    .option(
      '--format <format>',
      `output format (${REPORT_FORMATS.join('|')})`,
      parseFormat,
      'console',
    )
    .option(
      '--fail-on <severity>',
      'minimum severity for a non-zero exit code',
      parseSeverity,
      'high',
    )
    .option('--output <file>', 'write the report to a file instead of stdout')
    .action((targetPath: string | undefined, options: ScanCommandOptions) => {
      const { model, targetRootResolved } = discoverAgent(
        targetPath === undefined ? {} : { targetPath },
      );
      const { findings } = runChecks(model, ALL_CHECKS);

      const metadata: ScanMetadata = {
        target: model.targetRoot,
        targetRootResolved,
        timestamp: new Date().toISOString(),
        toolVersion: VERSION,
        inspectedCount: model.inspected.length,
        skippedCount: model.skipped.length,
      };

      const { output } = options;
      // Colors are meant for an interactive terminal; force plain text
      // before writing a saved report file so it isn't full of ANSI codes.
      const report = renderReport(options.format, findings, metadata, {
        console: output !== undefined ? { color: false } : {},
      });

      if (output !== undefined) {
        writeFileSync(output, report.endsWith('\n') ? report : `${report}\n`);
      } else {
        console.log(report);
      }

      if (findings.some((finding) => severityMeetsThreshold(finding.severity, options.failOn))) {
        process.exitCode = 1;
      }
    });

  return program;
}

export function run(argv: readonly string[]): void {
  const program = buildProgram();

  // The `checks` subcommand lands in Phase 5 alongside other CLI UX work.
  // Bare invocation shows usage rather than doing nothing silently.
  if (argv.length === 2) {
    program.outputHelp();
    return;
  }

  program.parse(argv);
}

const entryPoint = process.argv[1];
const isMainModule = entryPoint !== undefined && import.meta.url === `file://${entryPoint}`;
if (isMainModule) {
  run(process.argv);
}
