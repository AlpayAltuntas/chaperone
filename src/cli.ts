#!/usr/bin/env node
import { Command } from 'commander';
import { VERSION } from './version.js';

export function buildProgram(): Command {
  const program = new Command();

  program
    .name('chaperone')
    .description(
      'Security scanner that audits self-hosted personal AI agents for OWASP-LLM-mapped security weaknesses.',
    )
    .version(VERSION);

  return program;
}

export function run(argv: readonly string[]): void {
  const program = buildProgram();

  // Subcommands (scan, checks) land in later phases. For now, bare invocation
  // and --help both show usage rather than doing nothing silently.
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
