import { chapSec001Fixer } from './chapSec001Fixer.js';
import {
  chapInj004Fixer,
  chapNet001Fixer,
  chapObs004Fixer,
  chapSec002Fixer,
  chapSec003Fixer,
  chapSec006Fixer,
  chapSec008Fixer,
} from './fixers.js';
import type { FixPlan, Fixer } from './types.js';

export { applyFixPlan } from './apply.js';
export type { FixAction, FixChange, FixOptions, FixPlan, Fixer } from './types.js';

/** Every check with a working `chaperone fix` (PROPOSED_FIXES.md 5 widened this from one). */
export const FIXERS: readonly Fixer[] = [
  chapSec001Fixer,
  chapSec002Fixer,
  chapSec003Fixer,
  chapSec006Fixer,
  chapSec008Fixer,
  chapObs004Fixer,
  chapNet001Fixer,
  chapInj004Fixer,
];

export function findFixer(checkId: string): Fixer | undefined {
  return FIXERS.find((fixer) => fixer.checkId === checkId);
}

/** A safe-to-print, field-level summary of a proposed change — never a raw line-diff of file text, which could otherwise leak a real secret on the "before" side even by accident. */
export function renderFixPlan(plan: FixPlan): string {
  const files = [...new Set(plan.actions.map((action) => action.filePath))];
  const lines = [
    `Proposed fix for ${plan.checkId} (${files.join(', ')}):`,
    '',
    ...plan.changes.map(
      (change) => `  ${change.keyPath}: ${change.oldDisplayValue} -> ${change.newValue}`,
    ),
    '',
    `${String(plan.changes.length)} change${plan.changes.length === 1 ? '' : 's'} would be made.`,
    ...plan.notes.map((note) => `Note: ${note}`),
  ];
  return lines.join('\n');
}
