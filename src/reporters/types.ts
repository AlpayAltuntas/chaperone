import type { InspectedEntry, SkippedEntry } from '../model/types.js';

/**
 * Presentation-layer metadata every reporter (console, json, sarif)
 * receives alongside Finding[]. Kept separate from the AgentModel/Finding
 * zod schemas in model/types.ts since it describes the scan run itself,
 * not discovered agent data.
 *
 * Carries the full inspected/skipped inventory (not just counts) so
 * reporters can explain *why* nothing was found, not just that nothing
 * was — see instruction.md §9 ("inspected/skipped inventory") and the
 * Phase 5 "helpful messages when nothing is found" goal.
 */
export interface ScanMetadata {
  target: string;
  targetRootResolved: boolean;
  timestamp: string;
  toolVersion: string;
  inspected: InspectedEntry[];
  skipped: SkippedEntry[];
}
