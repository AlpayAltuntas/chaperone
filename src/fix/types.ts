import type { AgentModel } from '../model/types.js';

// Guided remediation (improvement_plan.md 3.14/Phase 22) — a materially
// different trust posture from `chaperone scan`'s read-only guardrail
// (§14), which is exactly why it's a separate command (`chaperone fix`,
// not a scan flag) with its own explicit write gate. See
// src/cli-fix.ts's own doc comment and DECISIONS.md, Phase 22.

/** One field-level change a Fixer proposes — never the real old value, only its already-masked display form (the same one CHAP-SEC-001's own finding already shows). */
export interface FixChange {
  keyPath: string;
  oldDisplayValue: string;
  newValue: string;
}

export interface FixPlan {
  checkId: string;
  filePath: string;
  changes: FixChange[];
  /** The full new file content — what --write actually writes, verbatim. */
  newContent: string;
}

/**
 * Computes a proposed remediation for one check's findings against an
 * already-discovered install. Pure — no I/O beyond `plan` itself
 * reading the one file it's about to propose editing (the same file
 * `discoverAgent` already read once to build `model`); never writes
 * anything. Returns `null` when there's nothing this fixer can propose
 * (e.g. no matching findings, or the install doesn't have the shape
 * this fixer targets).
 */
export interface Fixer {
  checkId: string;
  plan(model: AgentModel): FixPlan | null;
}
