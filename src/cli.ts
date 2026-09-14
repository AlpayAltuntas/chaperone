#!/usr/bin/env node
import { Command } from 'commander';
import { ALL_CHECKS } from './checks/index.js';
import { discoverAgent } from './discovery/index.js';
import { runChecks } from './engine/index.js';
import { formatConsoleReport } from './reporters/console.js';
import type { ScanMetadata } from './reporters/types.js';
import { VERSION } from './version.js';

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
    .action((targetPath: string | undefined) => {
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

      console.log(formatConsoleReport(findings, metadata));
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
