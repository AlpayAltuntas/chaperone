#!/usr/bin/env node
import { realpathSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { Command, InvalidArgumentError } from 'commander';
import { ALL_CHECKS } from './checks/index.js';
import { errorMessage } from './discovery/errors.js';
import { discoverAgent } from './discovery/index.js';
import { runChecks, type RunChecksResult } from './engine/index.js';
import { SEVERITY_ORDER, severityMeetsThreshold } from './engine/severity.js';
import type { Check } from './engine/types.js';
import type { AgentModel, Severity } from './model/types.js';
import { REPORT_FORMATS, renderReport, type ReportFormat } from './reporters/index.js';
import type { ScanMetadata } from './reporters/types.js';
import { VERSION } from './version.js';

interface ScanCommandOptions {
  format: ReportFormat;
  failOn: Severity;
  output?: string;
  color: boolean;
  only?: string[];
  skip?: string[];
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

function parseCheckIdList(value: string): string[] {
  return value
    .split(',')
    .map((id) => id.trim())
    .filter((id) => id.length > 0);
}

/** Renders the `checks` subcommand's catalog listing (id, title, severity). */
export function formatChecksList(checks: readonly Check[]): string {
  const lines = [`Chaperone check catalog (${String(checks.length)} checks)`, ''];
  for (const check of checks) {
    lines.push(`${check.id.padEnd(14)} ${check.severity.toUpperCase().padEnd(9)} ${check.title}`);
  }
  return lines.join('\n');
}

/** Applies --only/--skip and runs the check suite, erroring out (via `command`) if the filters leave nothing to run. */
function runCheckSuite(
  model: AgentModel,
  options: ScanCommandOptions,
  command: Command,
): RunChecksResult {
  const runOptions = {
    ...(options.only ? { only: options.only } : {}),
    ...(options.skip ? { skip: options.skip } : {}),
  };
  const result = runChecks(model, ALL_CHECKS, runOptions);

  if (result.checksRun.length === 0) {
    command.error(
      '--only/--skip left no checks to run. Run `chaperone checks` to see available check IDs.',
    );
  }

  return result;
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
    .option('--no-color', 'disable colored console output')
    .option('--only <ids>', 'run only the listed check IDs (comma-separated)', parseCheckIdList)
    .option('--skip <ids>', 'skip the listed check IDs (comma-separated)', parseCheckIdList)
    .action((targetPath: string | undefined, options: ScanCommandOptions, command: Command) => {
      // Everything below is wrapped so an unexpected bug (e.g. a reporter
      // throwing on some edge-case input) can never be mistaken for
      // "findings met --fail-on" — both would otherwise exit 1
      // indistinguishably to a CI pipeline reading only the exit code.
      // command.error() calls (unknown check ID, empty --only/--skip
      // result, the --output write failure below) are unaffected: without
      // .exitOverride() configured, commander calls process.exit()
      // directly rather than throwing, so they never reach this catch.
      try {
        const knownIds = new Set(ALL_CHECKS.map((check) => check.id));
        for (const id of [...(options.only ?? []), ...(options.skip ?? [])]) {
          if (!knownIds.has(id)) {
            command.error(
              `Unknown check ID: ${id}. Run \`chaperone checks\` to see available check IDs.`,
            );
          }
        }

        const { model, targetRootResolved } = discoverAgent(
          targetPath === undefined ? {} : { targetPath },
        );

        // No point evaluating checks against an empty/placeholder model
        // when no installation was even located — every "finding" would
        // be about a target that doesn't exist, which is confusing, not
        // helpful.
        const findings = targetRootResolved ? runCheckSuite(model, options, command).findings : [];

        const metadata: ScanMetadata = {
          target: model.targetRoot,
          targetRootResolved,
          timestamp: new Date().toISOString(),
          toolVersion: VERSION,
          inspected: model.inspected,
          skipped: model.skipped,
        };

        const { output } = options;
        // Colors are meant for an interactive terminal; force plain text
        // before writing a saved report file (or when --no-color is
        // passed) so a saved file isn't full of ANSI codes.
        const colorEnabled = output !== undefined ? false : options.color;
        const report = renderReport(options.format, findings, metadata, {
          console: { color: colorEnabled },
        });

        if (output !== undefined) {
          try {
            writeFileSync(output, report.endsWith('\n') ? report : `${report}\n`);
          } catch (err) {
            command.error(`Could not write report to '${output}': ${errorMessage(err)}`);
          }
        } else {
          console.log(report);
        }

        // A scan that never located an installation is treated the same
        // as hitting the fail-on threshold — automation should never
        // read a "nothing was scanned" run as a silent pass.
        const failed =
          !targetRootResolved ||
          findings.some((finding) => severityMeetsThreshold(finding.severity, options.failOn));
        if (failed) {
          process.exitCode = 1;
        }
      } catch (err) {
        console.error(`chaperone: unexpected error: ${errorMessage(err)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('checks')
    .description('List all available checks (id, title, severity)')
    .action(() => {
      console.log(formatChecksList(ALL_CHECKS));
    });

  // Alongside the built-in -V/--version flag (from .version() above) — §10
  // lists `chaperone version` as its own subcommand too.
  program
    .command('version')
    .description('Print version')
    .action(() => {
      console.log(VERSION);
    });

  return program;
}

export function run(argv: readonly string[]): void {
  const program = buildProgram();

  // Bare invocation shows usage rather than doing nothing silently.
  if (argv.length === 2) {
    program.outputHelp();
    return;
  }

  program.parse(argv);
}

/**
 * True when this module was invoked directly as the entry script (vs.
 * imported for its exports, as every test in this repo does).
 *
 * `entryPoint` (process.argv[1]) is the literal path Node was invoked
 * with — when installed via npm, that's the symlink in
 * `node_modules/.bin/`, not the real file. `moduleUrl` (import.meta.url)
 * resolves through the symlink, so a naive string comparison never
 * matches once this ships as a real package (caught by installing a
 * packed tarball before publishing — see DECISIONS.md). Resolve both
 * sides through the real path first. Takes both as parameters, rather
 * than reading `process.argv`/`import.meta.url` directly, so this exact
 * symlink-resolution logic is unit-testable without a subprocess.
 */
export function isMainModule(entryPoint: string | undefined, moduleUrl: string): boolean {
  if (entryPoint === undefined) {
    return false;
  }
  try {
    return moduleUrl === pathToFileURL(realpathSync(entryPoint)).href;
  } catch {
    return false;
  }
}

if (isMainModule(process.argv[1], import.meta.url)) {
  run(process.argv);
}
