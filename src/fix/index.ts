import { chapSec001Fixer } from './chapSec001Fixer.js';
import type { FixPlan, Fixer } from './types.js';

export type { FixChange, FixPlan, Fixer } from './types.js';

/**
 * Every check with a working `chaperone fix` — deliberately just one
 * for v1 (improvement_plan.md 3.14's DoD: "at least one check"), not
 * parity with the full 29-check catalog. A clear, obvious place to
 * register another Fixer later.
 */
export const FIXERS: readonly Fixer[] = [chapSec001Fixer];

export function findFixer(checkId: string): Fixer | undefined {
  return FIXERS.find((fixer) => fixer.checkId === checkId);
}

/** A safe-to-print, field-level summary of a proposed change — never a raw line-diff of file text, which could otherwise leak a real secret on the "before" side even by accident. */
export function renderFixPlan(plan: FixPlan): string {
  const lines = [
    `Proposed fix for ${plan.checkId} in ${plan.filePath}:`,
    '',
    ...plan.changes.map(
      (change) => `  ${change.keyPath}: ${change.oldDisplayValue} -> ${change.newValue}`,
    ),
    '',
    `${String(plan.changes.length)} field${plan.changes.length === 1 ? '' : 's'} would be changed.`,
  ];
  return lines.join('\n');
}
