import { appendFileSync, chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import type { FixAction, FixPlan } from './types.js';

/** Performs a plan's actions in order. Only ever called after the plan has been printed and --write confirmed. */
export function applyFixPlan(plan: FixPlan): string[] {
  return plan.actions.map(applyAction);
}

function applyAction(action: FixAction): string {
  switch (action.kind) {
    case 'write-file':
      writeFileSync(
        action.filePath,
        action.content,
        action.mode === undefined ? {} : { mode: action.mode },
      );
      return `Wrote ${action.filePath}.`;
    case 'append-lines': {
      const existing = existsSync(action.filePath) ? readFileSync(action.filePath, 'utf8') : null;
      const present = new Set((existing ?? '').split(/\r?\n/).map((line) => line.trim()));
      const missing = action.lines.filter((line) => !present.has(line.trim()));
      if (missing.length === 0) {
        return `${action.filePath} already has every line.`;
      }
      const prefix =
        existing !== null && existing.length > 0 && !existing.endsWith('\n') ? '\n' : '';
      if (existing === null) {
        writeFileSync(
          action.filePath,
          `${missing.join('\n')}\n`,
          action.mode === undefined ? {} : { mode: action.mode },
        );
      } else {
        appendFileSync(action.filePath, `${prefix}${missing.join('\n')}\n`);
      }
      return `Appended ${String(missing.length)} line${missing.length === 1 ? '' : 's'} to ${action.filePath}.`;
    }
    case 'chmod':
      chmodSync(action.filePath, action.mode);
      return `Set ${action.filePath} to mode ${action.mode.toString(8).padStart(3, '0')}.`;
  }
}
