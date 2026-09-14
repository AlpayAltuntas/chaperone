#!/usr/bin/env node
import { Command } from 'commander';
import { discoverAgent } from './discovery/index.js';
import { formatInventorySummary } from './discovery/inventory.js';
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
    .description('Scan an agent installation and print a discovery inventory')
    .action((targetPath: string | undefined) => {
      const { model, targetRootResolved } = discoverAgent(
        targetPath === undefined ? {} : { targetPath },
      );
      for (const line of formatInventorySummary(model, targetRootResolved)) {
        console.log(line);
      }
    });

  return program;
}

export function run(argv: readonly string[]): void {
  const program = buildProgram();

  // The `checks` subcommand lands once the check engine exists (Phase 2+).
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
