import type { AgentModel } from '../model/types.js';

// Guided remediation (improvement_plan.md 3.14/Phase 22) — a materially
// different trust posture from `chaperone scan`'s read-only guardrail
// (§14), which is exactly why it's a separate command (`chaperone fix`,
// not a scan flag) with its own explicit write gate. See DECISIONS.md,
// Phase 22. Widened to several fixers in PROPOSED_FIXES.md 5: every one
// is local and reversible, and is shown in full before anything is
// written.

/** One change a Fixer proposes, as shown to the user — never a real secret, only its masked display form. */
export interface FixChange {
  /** What changes: a config key path, or a file path. */
  keyPath: string;
  oldDisplayValue: string;
  newValue: string;
}

/** One filesystem operation a plan performs when applied. */
export type FixAction =
  /** Replace a file's content (created with `mode` if it doesn't exist). */
  | { kind: 'write-file'; filePath: string; content: string; mode?: number }
  /** Append lines not already present (creating the file with `mode`). */
  | { kind: 'append-lines'; filePath: string; lines: string[]; mode?: number }
  | { kind: 'chmod'; filePath: string; mode: number };

export interface FixPlan {
  checkId: string;
  changes: FixChange[];
  actions: FixAction[];
  /** Advice printed after the plan: variables to export, credentials to rotate. */
  notes: string[];
}

/** Options that widen what a fixer proposes. */
export interface FixOptions {
  /** CHAP-SEC-001: also move the literal values into a 0600 `.env` file (PROPOSED_FIXES.md 5). */
  writeEnv?: boolean;
}

/**
 * Computes a proposed remediation for one check's findings against an
 * already-discovered install. Never writes anything; reads at most the
 * files it is about to propose editing. Returns `null` when there is
 * nothing to fix.
 */
export interface Fixer {
  checkId: string;
  plan(model: AgentModel, options?: FixOptions): FixPlan | null;
}
