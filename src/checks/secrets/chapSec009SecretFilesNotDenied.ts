import type { Check } from '../../engine/types.js';
import { permissionRules, type PermissionRule } from '../shared/claudeCode.js';

const ID = 'CHAP-SEC-009';
const TITLE = 'Secret files readable by Claude Code';
const OWASP = 'LLM06: Sensitive Information Disclosure';
const REMEDIATION =
  'Add `Read` deny rules for secret files, e.g. `"deny": ["Read(./.env)", "Read(./.env.*)", "Read(~/.ssh/**)"]`. Claude Code reads files in the working directory without asking, and a `.claudeignore` file has no effect.';

const SENSITIVE: ReadonlyArray<{ label: string; covered: (specifier: string) => boolean }> = [
  { label: '.env files', covered: (s) => s.includes('.env') || /\*\*$/.test(s) },
  { label: '~/.ssh', covered: (s) => s.includes('.ssh') || s === '~/**' || s === '//**' },
];

/** Flags Claude Code settings with no `Read` deny rule for `.env` files or `~/.ssh` (PROPOSED_FIXES.md 6.1). */
export const chapSec009SecretFilesNotDenied: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'secrets',
  owasp: OWASP,
  appliesToProfiles: ['claude-code'],
  detects:
    'Claude Code settings with no deny rule keeping its file tools away from common secret files: `.env` files in the project and SSH keys in `~/.ssh`.',
  heuristic:
    'Across every settings file read, no `permissions.deny` rule for `Read` (bare, or with a path containing `.env`, or a recursive `**` pattern) covers `.env` files, or none (containing `.ssh`, or `~/**`/`//**`) covers `~/.ssh`. Only reported when at least one settings file exists. Path coverage is approximate: it checks for the file name in the rule, not full glob matching.',
  remediation: REMEDIATION,
  run(model) {
    const first = model.claudeCodeSettings[0];
    if (first === undefined) {
      return [];
    }
    const readDenies: PermissionRule[] = permissionRules(model, 'deny').filter(
      (rule) => rule.tool === 'Read' || rule.tool === '*',
    );
    if (readDenies.some((rule) => rule.specifier === null || rule.specifier === '*')) {
      return [];
    }
    const missing = SENSITIVE.filter(
      ({ covered }) => !readDenies.some((rule) => covered(rule.specifier ?? '')),
    ).map(({ label }) => label);
    if (missing.length === 0) {
      return [];
    }
    const target = model.claudeCodeSettings.find((file) => file.scope === 'project') ?? first;
    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'secrets',
        owasp: OWASP,
        message: `No Read deny rule covers ${missing.join(' or ')}, so Claude Code can read ${missing.length === 1 ? 'them' : 'these'} without asking, and anything it reads can end up in a prompt or a tool call.`,
        location: {
          filePath: target.path,
          line: target.keyLines['permissions.deny'] ?? target.keyLines['permissions'] ?? null,
          detail: 'permissions.deny',
        },
        remediation: REMEDIATION,
      },
    ];
  },
};
