import { extractEnvVarName } from '../../discovery/configParser.js';
import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SEC-007';
const TITLE = "Config references an environment variable that isn't set";
const OWASP = 'LLM06: Sensitive Information Disclosure';

/**
 * Advisory/best-effort only (improvement_plan.md 2.3): Chaperone runs as
 * a separate process from the agent and may not share its real
 * environment — e.g. the agent could be launched via systemd/launchd
 * with its own EnvironmentFile that Chaperone never sees. The caveat is
 * stated directly in the finding message, not just CHECKS.md, per the
 * plan's explicit instruction. Only checks bare `${VAR}`/`$VAR`/`env:VAR`
 * references (see configParser.ts's extractEnvVarName) — a reference
 * with a `:-`/`:=`/`:?`/`:+` fallback resolves to something even when
 * the variable itself is unset, so Chaperone can't say anything useful
 * about those and skips them rather than risk a false positive.
 */
export const chapSec007EnvVarNotSet: Check = {
  id: ID,
  title: TITLE,
  severity: 'low',
  category: 'secrets',
  owasp: OWASP,
  run(model) {
    if (model.config.path === null) {
      return [];
    }

    const findings = [];
    for (const field of model.config.secretFields) {
      if (!field.looksLikeEnvReference) {
        continue;
      }
      const varName = extractEnvVarName(field.displayValue);
      if (varName === null) {
        continue;
      }
      const value = process.env[varName];
      if (value !== undefined && value !== '') {
        continue;
      }

      findings.push({
        checkId: ID,
        title: TITLE,
        severity: 'low' as const,
        category: 'secrets' as const,
        owasp: OWASP,
        message: `Config field '${field.keyPath}' references environment variable '${varName}', which is not set (or is empty) in Chaperone's own process environment. This is advisory and low-confidence: Chaperone runs as a separate process from the agent and may not share its real environment — verify directly rather than treating this as confirmed.`,
        location: { filePath: model.config.path, line: null, detail: field.keyPath },
        remediation: `Confirm '${varName}' is actually set in the environment the agent runs under; an unresolved reference can mean the agent starts with an empty or broken credential.`,
      });
    }
    return findings;
  },
};
