import type { AgentModel, CheckCategory, Finding, Severity } from '../model/types.js';

/**
 * A single security check: a pure function over the discovered AgentModel.
 * Checks never do I/O — all reads happen in discovery — which keeps them
 * deterministic and trivially testable against a fixture model.
 */
export interface Check {
  id: string;
  title: string;
  severity: Severity;
  category: CheckCategory;
  owasp: string;
  run(model: AgentModel): Finding[];
}
