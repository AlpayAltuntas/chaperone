import type { Check } from '../../engine/types.js';

const ID = 'CHAP-OBS-002';
const TITLE = 'Sensitive data in plaintext logs';
const OWASP = 'LLM06: Sensitive Information Disclosure';

/** Flags logging config that doesn't confirm secrets/message bodies are redacted before being written. */
export const chapObs002UnredactedLogs: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'observability',
  owasp: OWASP,
  run(model) {
    if (!model.logging.present || model.logging.redactSecrets === true) {
      return [];
    }

    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'observability',
        owasp: OWASP,
        message:
          'Logging config does not confirm secrets/message bodies are redacted before being written to logs.',
        location: {
          filePath: model.logging.path ?? model.config.path,
          line: null,
          detail: 'logging.redact_secrets',
        },
        remediation:
          'Redact secrets and sensitive message content before logging, and restrict access to the log file.',
      },
    ];
  },
};
