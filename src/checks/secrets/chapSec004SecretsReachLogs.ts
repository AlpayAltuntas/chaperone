import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SEC-004';
const TITLE = 'Secrets likely to reach logs';
const OWASP = 'LLM06: Sensitive Information Disclosure';

const VERBOSE_LEVEL_PATTERN = /^(debug|trace|verbose)$/i;

/**
 * Flags a verbose/debug log level while literal secrets are configured
 * (request/response logging at that level routinely captures raw payloads),
 * or a log file that's itself readable by group/other.
 */
export const chapSec004SecretsReachLogs: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'secrets',
  owasp: OWASP,
  detects:
    "Verbose logging that's likely to capture secrets, or a log file itself exposed to other local users.",
  heuristic:
    'Fires when either: the log level is `debug`/`trace`/`verbose` while the config holds a literal secret, or the log file is readable by group/other. Either reason alone is enough; both are reported together when both hold.',
  remediation:
    'Raise the log level away from debug/trace, redact secrets before logging, and restrict the log file to owner-only access.',
  run(model) {
    if (!model.logging.present) {
      return [];
    }

    const hasLiteralSecret = model.config.secretFields.some(
      (field) => !field.looksLikeEnvReference,
    );
    const verboseWithSecrets =
      model.logging.level !== null &&
      VERBOSE_LEVEL_PATTERN.test(model.logging.level) &&
      hasLiteralSecret;

    const logPermissionFact =
      model.logging.path !== null
        ? model.permissions.find((p) => p.path === model.logging.path)
        : undefined;
    const worldReadableLog =
      logPermissionFact !== undefined &&
      logPermissionFact.exists &&
      logPermissionFact.groupOrOtherReadable === true;

    if (!verboseWithSecrets && !worldReadableLog) {
      return [];
    }

    const reasons: string[] = [];
    if (verboseWithSecrets) {
      reasons.push(
        `log level '${model.logging.level ?? ''}' is verbose while literal secrets are configured`,
      );
    }
    if (worldReadableLog) {
      reasons.push('the log file is readable by group or other');
    }

    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'secrets',
        owasp: OWASP,
        message: `Secrets are likely to reach logs: ${reasons.join('; ')}.`,
        location: {
          filePath: model.logging.path ?? model.config.path,
          line: null,
          detail: 'logging',
        },
        remediation:
          'Raise the log level away from debug/trace, redact secrets before logging, and restrict the log file to owner-only access.',
      },
    ];
  },
};
