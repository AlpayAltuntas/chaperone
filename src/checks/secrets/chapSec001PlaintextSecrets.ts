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
  detects:
    'API keys, tokens, passwords, and similar credentials stored directly in the config file as literal values.',
  heuristic:
    'A config key whose name looks secret-bearing (`api_key`, `token`, `secret`, `password`, `credential`, case-insensitive) holds a literal string value rather than an indirect reference (`${VAR}`, `$VAR`, `env:VAR`). The literal value is masked (e.g. `sk-…wxyz`) before it ever reaches this check or any report — the real value is never printed. For a YAML config, the finding includes a real source line number (via `YAML.parseDocument`); a JSON config has no equivalent free CST-with-positions, so its findings report a `null` line.',
  remediation:
    'Move the value to an environment variable or a secrets manager and reference it indirectly in config.',
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
        location: { filePath: model.config.path, line: field.line, detail: field.keyPath },
        remediation:
          'Move this value to an environment variable or a secrets manager and reference it indirectly in config (e.g. ${VAR} or env:VAR).',
      }));
  },
};
