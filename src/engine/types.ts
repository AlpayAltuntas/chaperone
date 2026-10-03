import type { DiscoveryProfile } from '../discovery/index.js';
import type { AgentModel, CheckCategory, Finding, Severity } from '../model/types.js';

/**
 * A single security check: a pure function over the discovered AgentModel.
 * Checks never do I/O — all reads happen in discovery — which keeps them
 * deterministic and trivially testable against a fixture model.
 *
 * `detects`/`heuristic`/`remediation` are the check's general-purpose doc
 * text (improvement_plan.md 4.2/3.7) — CHECKS.md's catalog is generated
 * from these (`npm run docs:checks`), and `chaperone explain <id>` reads
 * the same fields, so the code and the docs can't drift apart. Distinct
 * from a `Finding`'s own `message`/`remediation`, which are per-instance
 * and may interpolate specific values (a field name, a file path, ...).
 */
export interface Check {
  id: string;
  title: string;
  severity: Severity;
  category: CheckCategory;
  owasp: string;
  detects: string;
  heuristic: string;
  remediation: string;
  /** Overrides the plain severity label in generated docs, e.g. "Info (demoted from High — see below)". Rare — only used where a check's own severity needs a documented caveat. */
  severityNote?: string;
  /**
   * Discovery profiles this check is meaningful under; omitted means all.
   * A check that only reads keys from the default profile's config format
   * (`trust.*`, `logging.*`, ...) can't say anything true about an MCP
   * config, which has no such keys, so the engine reports it as not
   * applicable there instead of running it (PROPOSED_FIXES.md 2.8).
   */
  appliesToProfiles?: readonly DiscoveryProfile[];
  run(model: AgentModel): Finding[];
}
