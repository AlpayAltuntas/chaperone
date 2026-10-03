import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SEC-001';
const TITLE = 'Plaintext secrets in config';
const OWASP = 'LLM06: Sensitive Information Disclosure';

/**
 * Flags config fields whose key name looks secret-bearing (api_key, token,
 * password, ...) and whose value is a literal rather than an indirect
 * environment-variable reference, plus any field whose value alone is
 * secret-shaped (a provider-prefixed token, a bearer credential, a URL
 * password; PROPOSED_FIXES.md 3.1). Discovery has already masked the literal
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
    'API keys, tokens, passwords, and similar credentials stored directly in the config file as literal values, whether under a secret-named key or recognizable from the value itself.',
  heuristic:
    'A config key whose name looks secret-bearing (`api_key`, `token`, `secret`, `password`, `credential`, case-insensitive) holds a literal string value rather than an indirect reference (`${VAR}`, `$VAR`, `env:VAR`). Keys ending in `auth`, `authorization`, `bearer`, `cookie`, or `session` count only when the value looks like a credential rather than a word. Independently of the key name, a value is flagged when it matches a high-precision pattern: a provider-prefixed token (`sk-ant-`, `sk-proj-`, `ghp_`, `github_pat_`, `xoxb-`, `AKIA`, `AIza`, `glpat-`, `npm_`, `hf_`, `sk_live_`), a `Bearer`/`Basic` credential, a PEM private key, or a password in a URL (`https://user:pass@host`). No entropy guessing. The literal value is masked (e.g. `sk-…wxyz`) before it ever reaches this check or any report — the real value is never printed. Findings include the source line, for YAML and JSON configs alike (JSON is parsed for positions with `YAML.parseDocument`).',
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
        message:
          field.detectedBy === 'value-pattern'
            ? `Config field '${field.keyPath}' holds a value that looks like a ${field.pattern ?? 'secret'} (${field.displayValue}), recognized from the value itself. Literal credentials belong in an environment variable, not the config.`
            : `Config field '${field.keyPath}' holds a literal secret value (${field.displayValue}) instead of an environment-variable reference.`,
        location: { filePath: model.config.path, line: field.line, detail: field.keyPath },
        remediation:
          'Move this value to an environment variable or a secrets manager and reference it indirectly in config (e.g. ${VAR} or env:VAR).',
      }));
  },
};
