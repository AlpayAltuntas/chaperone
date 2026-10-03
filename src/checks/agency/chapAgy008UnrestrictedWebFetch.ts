import type { Check } from '../../engine/types.js';
import { permissionRules } from '../shared/claudeCode.js';

const ID = 'CHAP-AGY-008';
const TITLE = 'Web fetches pre-approved for every domain';
const OWASP = 'LLM08: Excessive Agency';
const REMEDIATION =
  'Allow only the domains the project needs, e.g. `WebFetch(domain:docs.example.com)`. Fetched pages are untrusted input, so each new domain is a new prompt-injection source.';

/** Flags a `permissions.allow` rule that pre-approves WebFetch for any domain (PROPOSED_FIXES.md 6.1). */
export const chapAgy008UnrestrictedWebFetch: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'agency',
  owasp: OWASP,
  appliesToProfiles: ['claude-code'],
  detects:
    'A Claude Code `permissions.allow` rule that lets it fetch any URL without asking: a channel for both data exfiltration and prompt injection from attacker-controlled pages.',
  heuristic:
    'A bare `WebFetch` allow rule, or `WebFetch(domain:*)`. A domain-scoped rule (`WebFetch(domain:example.com)`, `WebFetch(domain:*.example.com)`) is fine.',
  remediation: REMEDIATION,
  run(model) {
    return permissionRules(model, 'allow')
      .filter(
        (rule) =>
          rule.tool === 'WebFetch' && (rule.specifier === null || rule.specifier === 'domain:*'),
      )
      .map((rule) => ({
        checkId: ID,
        title: TITLE,
        severity: 'medium' as const,
        category: 'agency' as const,
        owasp: OWASP,
        message: `The allow rule '${rule.rule}' (${rule.file.scope} settings) lets Claude Code fetch any URL without asking.`,
        location: { filePath: rule.file.path, line: rule.line, detail: rule.rule },
        remediation: REMEDIATION,
      }));
  },
};
