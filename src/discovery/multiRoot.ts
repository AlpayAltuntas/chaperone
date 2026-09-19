import { readdirSync } from 'node:fs';
import path from 'node:path';
import { errorMessage } from './errors.js';
import { expandHome } from './pathUtils.js';

// Multi-root/batch scanning (improvement_plan.md 3.2/Phase 20) —
// `--all <pattern>`. Deliberately NOT a general-purpose glob engine (no
// new dependency, no `**`/character-class support): the plan's own
// example (`~/agents/*`) is the one shape this needs to handle well —
// "every immediate subdirectory of a parent directory". A pattern with
// no trailing `/*` is treated as a single literal directory, so `--all`
// degenerates cleanly to ordinary single-target scanning when there's
// nothing to expand.
//
// The shell itself would normally expand a bare `~/agents/*` before
// Chaperone ever sees it — this only does anything useful when the
// caller quotes the pattern (`--all '~/agents/*'`), which the CLI's own
// help text says explicitly.

/** Resolves `--all <pattern>` to the list of target root directories to scan. Throws if a trailing-`/*` pattern's parent directory can't be listed. */
export function expandAllPattern(pattern: string): string[] {
  const expanded = expandHome(pattern);
  if (!expanded.endsWith('/*')) {
    return [path.resolve(expanded)];
  }

  const parent = path.resolve(expanded.slice(0, -2) || '/');
  let entries: string[];
  try {
    entries = readdirSync(parent, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => path.join(parent, entry.name))
      .sort();
  } catch (err) {
    throw new Error(`could not list '${parent}' for --all: ${errorMessage(err)}`, { cause: err });
  }
  return entries;
}
