/**
 * Presentation-layer metadata every reporter (console, and json/sarif in a
 * later phase) receives alongside Finding[]. Kept separate from the
 * AgentModel/Finding zod schemas in model/types.ts since it describes the
 * scan run itself, not discovered agent data.
 */
export interface ScanMetadata {
  target: string;
  targetRootResolved: boolean;
  timestamp: string;
  toolVersion: string;
  inspectedCount: number;
  skippedCount: number;
}
