import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SEC-001';
const TITLE = 'Plaintext secrets in config';
const OWASP = 'LLM06: Sensitive Information Disclosure';

/**
 * Flags config fields whose key name looks secret-bearing (api_key, token,
 * password, ...) and whose value is a literal rather than an indirect
 * environment-variable reference. Discovery has already masked the literal
 * value before it ever reaches this check (see configParser.ts) — the
 * masked display form is all this check ever sees or reports.
 */
export const chapSec001PlaintextSecrets: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'secrets',
  owasp: OWASP,
  run(model) {
    if (model.config.path === null) {
      return [];
    }

    return model.config.secretFields
      .filter((field) => !field.looksLikeEnvReference)
      .map((field) => ({
        checkId: ID,
        title: TITLE,
        severity: 'high',
        category: 'secrets',
        owasp: OWASP,
        message: `Config field '${field.keyPath}' holds a literal secret value (${field.displayValue}) instead of an environment-variable reference.`,
        location: { filePath: model.config.path, line: null, detail: field.keyPath },
        remediation:
          'Move this value to an environment variable or a secrets manager and reference it indirectly in config (e.g. ${VAR} or env:VAR).',
      }));
  },
};
