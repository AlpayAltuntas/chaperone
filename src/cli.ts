#!/usr/bin/env node
import { realpathSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { Command, InvalidArgumentError, Option } from 'commander';
import { ALL_CHECKS } from './checks/index.js';
import { findNewFindings, loadBaseline } from './config/baseline.js';
import {
  applyChaperoneConfig,
  DEFAULT_CONFIG_FILENAME,
  loadChaperoneConfig,
} from './config/chaperoneConfig.js';
import { errorMessage } from './discovery/errors.js';
import { discoverAgent } from './discovery/index.js';
import { runChecks, type RunChecksResult } from './engine/index.js';
import { SEVERITY_ORDER, severityMeetsThreshold } from './engine/severity.js';
import type { Check } from './engine/types.js';
import {
  CheckCategorySchema,
  type AgentModel,
  type CheckCategory,
  type Finding,
  type Severity,
} from './model/types.js';
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
  onlyCategory?: CheckCategory[];
  skipCategory?: CheckCategory[];
  minSeverity?: Severity;
  quiet?: boolean;
  summaryOnly?: boolean;
  config?: string;
  baseline?: string;
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

const CHECK_CATEGORIES = CheckCategorySchema.options;

function parseCategoryList(value: string): CheckCategory[] {
  const raw = value
    .split(',')
    .map((category) => category.trim())
    .filter((category) => category.length > 0);
  for (const category of raw) {
    if (!(CHECK_CATEGORIES as readonly string[]).includes(category)) {
      throw new InvalidArgumentError(`must be one of: ${CHECK_CATEGORIES.join(', ')}`);
    }
  }
  return raw as CheckCategory[];
}

/** A display filter over already-run findings — never affects --fail-on, which always evaluates the full, unfiltered result (improvement_plan.md 3.8). */
function applyDisplayFilters(findings: readonly Finding[], options: ScanCommandOptions): Finding[] {
  let result = [...findings];
  if (options.onlyCategory !== undefined) {
    const set = new Set(options.onlyCategory);
    result = result.filter((finding) => set.has(finding.category));
  }
  if (options.skipCategory !== undefined) {
    const set = new Set(options.skipCategory);
    result = result.filter((finding) => !set.has(finding.category));
  }
  if (options.minSeverity !== undefined) {
    const threshold = options.minSeverity;
    result = result.filter((finding) => severityMeetsThreshold(finding.severity, threshold));
  }
  return result;
}

/** Renders the `checks` subcommand's catalog listing (id, title, severity). */
export function formatChecksList(checks: readonly Check[]): string {
  const lines = [`Chaperone check catalog (${String(checks.length)} checks)`, ''];
  for (const check of checks) {
    lines.push(`${check.id.padEnd(14)} ${check.severity.toUpperCase().padEnd(9)} ${check.title}`);
  }
  return lines.join('\n');
}

/**
 * Renders the `explain <check-id>` subcommand's full detail for one
 * check — the same detects/heuristic/remediation fields CHECKS.md is
 * generated from (improvement_plan.md 3.7/4.2), so this and the doc
 * can't drift apart.
 */
export function formatCheckExplanation(check: Check): string {
  const severityLabel = check.severityNote ?? check.severity.toUpperCase();
  return [
    `${check.id} — ${check.title}`,
    '',
    `Severity: ${severityLabel}`,
    `Category: ${check.category}`,
    `OWASP:    ${check.owasp}`,
    '',
    'Detects:',
    `  ${check.detects}`,
    '',
    'Heuristic:',
    `  ${check.heuristic}`,
    '',
    'Remediation:',
    `  ${check.remediation}`,
  ].join('\n');
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
    .addOption(
      new Option('--format <format>', `output format (${REPORT_FORMATS.join('|')})`)
        .argParser(parseFormat)
        .default('console')
        .env('CHAPERONE_FORMAT'),
    )
    .addOption(
      new Option('--fail-on <severity>', 'minimum severity for a non-zero exit code')
        .argParser(parseSeverity)
        .default('high')
        .env('CHAPERONE_FAIL_ON'),
    )
    .addOption(
      new Option('--output <file>', 'write the report to a file instead of stdout').env(
        'CHAPERONE_OUTPUT',
      ),
    )
    .option('--no-color', 'disable colored console output')
    .option('--only <ids>', 'run only the listed check IDs (comma-separated)', parseCheckIdList)
    .option('--skip <ids>', 'skip the listed check IDs (comma-separated)', parseCheckIdList)
    .addOption(
      new Option(
        '--only-category <categories>',
        `only display findings in these categories, comma-separated (${CHECK_CATEGORIES.join('|')}) — a display filter, doesn't change which checks run or --fail-on`,
      )
        .argParser(parseCategoryList)
        .env('CHAPERONE_ONLY_CATEGORY'),
    )
    .addOption(
      new Option(
        '--skip-category <categories>',
        'hide findings in these categories, comma-separated — a display filter, same caveat as --only-category',
      )
        .argParser(parseCategoryList)
        .env('CHAPERONE_SKIP_CATEGORY'),
    )
    .addOption(
      new Option(
        '--min-severity <severity>',
        'only display findings at or above this severity — a display filter, distinct from --fail-on (which always evaluates every finding)',
      )
        .argParser(parseSeverity)
        .env('CHAPERONE_MIN_SEVERITY'),
    )
    .addOption(
      new Option(
        '--quiet',
        'print one compact line per finding (id + severity) instead of full detail',
      ).conflicts('summaryOnly'),
    )
    .addOption(
      new Option(
        '--summary-only',
        'print only the summary line and posture score, no findings',
      ).conflicts('quiet'),
    )
    .addOption(
      new Option(
        '--config <file>',
        `suppression/override config file (default: ./${DEFAULT_CONFIG_FILENAME} if present) — severityOverrides, ignore (with expires), disabledChecks, scoreWeights`,
      ).env('CHAPERONE_CONFIG'),
    )
    .addOption(
      new Option(
        '--baseline <file>',
        'a prior JSON report (chaperone scan --format json --output <file>) — report only findings new since then',
      ).env('CHAPERONE_BASELINE'),
    )
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

        let rcConfig;
        try {
          rcConfig = loadChaperoneConfig(options.config).config;
        } catch (err) {
          command.error(errorMessage(err));
        }

        let baseline;
        if (options.baseline !== undefined) {
          try {
            baseline = loadBaseline(options.baseline);
          } catch (err) {
            command.error(errorMessage(err));
          }
        }

        // disabledChecks (improvement_plan.md 3.4) feeds the same --skip
        // mechanism a check-ID typo on the command line already goes
        // through, so an unknown ID here is validated identically.
        const disabledChecks = rcConfig.disabledChecks ?? [];
        if (disabledChecks.length > 0) {
          options.skip = [...(options.skip ?? []), ...disabledChecks];
        }

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
        const rawFindings = targetRootResolved
          ? runCheckSuite(model, options, command).findings
          : [];

        // severityOverrides/ignore are a real reclassification the user
        // has consciously made, so — unlike the purely cosmetic display
        // filters just below — this result feeds --fail-on and the score
        // too, not just what's rendered (improvement_plan.md 3.4).
        const { findings: configAdjustedFindings, warnings: configWarnings } = applyChaperoneConfig(
          rawFindings,
          rcConfig,
          knownIds,
        );
        for (const warning of configWarnings) {
          console.error(`chaperone: warning: ${warning}`);
        }

        // --baseline (improvement_plan.md 3.5) is, like severityOverrides/
        // ignore just above, a real narrowing of what "counts" — the
        // whole point is to let --fail-on gate on new findings only, not
        // just to hide old ones from the printed report.
        const findings =
          baseline !== undefined
            ? findNewFindings(configAdjustedFindings, baseline)
            : configAdjustedFindings;

        // Category/severity filters are purely presentational — --fail-on
        // below always evaluates the full (config-/baseline-adjusted)
        // `findings`, never this filtered view (improvement_plan.md 3.8).
        const displayFindings = applyDisplayFilters(findings, options);

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
        const report = renderReport(options.format, displayFindings, metadata, {
          console: {
            color: colorEnabled,
            ...(options.quiet !== undefined ? { quiet: options.quiet } : {}),
            ...(options.summaryOnly !== undefined ? { summaryOnly: options.summaryOnly } : {}),
          },
          ...(rcConfig.scoreWeights !== undefined ? { scoreWeights: rcConfig.scoreWeights } : {}),
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

  program
    .command('explain')
    .argument('<check-id>', 'a check ID, e.g. CHAP-SEC-001 (see `chaperone checks`)')
    .description('Print full detail (detects, heuristic, remediation) for one check')
    .action((checkId: string, _options: unknown, command: Command) => {
      const check = ALL_CHECKS.find((c) => c.id === checkId);
      if (check === undefined) {
        command.error(
          `Unknown check ID: ${checkId}. Run \`chaperone checks\` to see available check IDs.`,
        );
      }
      console.log(formatCheckExplanation(check));
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
