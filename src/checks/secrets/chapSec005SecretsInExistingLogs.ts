import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SEC-005';
const TITLE = 'Secret already present in existing log content';
const OWASP = 'LLM06: Sensitive Information Disclosure';

/**
 * Distinct from CHAP-SEC-004/CHAP-OBS-002, which only reason about
 * whether logging *config* is likely to leak secrets going forward.
 * This fires on evidence a secret has *already* leaked into the log
 * file from a past run (improvement_plan.md 1.8/2.1) — e.g. someone
 * temporarily raised the log level to chase a bug, a request containing
 * an API key got logged, then the level was turned back down; the
 * leaked value sits in the log file regardless of current config.
 */
export const chapSec005SecretsInExistingLogs: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'secrets',
  owasp: OWASP,
  run(model) {
    if (model.logging.path === null) {
      return [];
    }

    return model.logging.existingSecretMatches.map((match) => ({
      checkId: ID,
      title: TITLE,
      severity: 'high' as const,
      category: 'secrets' as const,
      owasp: OWASP,
      message: `A secret-shaped value for '${match.keyName}' (${match.displayValue}) was found in the existing log file content — a past run appears to have already leaked it, regardless of the current logging configuration.`,
      location: { filePath: model.logging.path, line: null, detail: match.keyName },
      remediation:
        'Rotate the leaked credential, purge or redact the log file, and fix the logging behavior that caused it to be written (see CHAP-SEC-004/CHAP-OBS-002).',
    }));
  },
};
