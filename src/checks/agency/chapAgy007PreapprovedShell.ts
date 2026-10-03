import type { Check } from '../../engine/types.js';
import { permissionRules } from '../shared/claudeCode.js';

const ID = 'CHAP-AGY-007';
const TITLE = 'Shell commands pre-approved too broadly';
const OWASP = 'LLM08: Excessive Agency';
const REMEDIATION =
  'Replace the rule with the specific commands the project needs (e.g. `Bash(npm run test *)`), and leave interpreters, downloads, deletes, and privilege escalation to a prompt.';

// Commands that run arbitrary code, fetch it, delete data, or escalate.
// Pre-approving any prefix of these is close to pre-approving everything.
const RISKY_COMMANDS = new Set([
  'sh',
  'bash',
  'zsh',
  'fish',
  'pwsh',
  'powershell',
  'python',
  'python3',
  'node',
  'deno',
  'bun',
  'perl',
  'ruby',
  'npx',
  'bunx',
  'eval',
  'exec',
  'xargs',
  'env',
  'sudo',
  'su',
  'doas',
  'curl',
  'wget',
  'rm',
  'dd',
  'chmod',
  'chown',
  'ssh',
  'scp',
  'Invoke-Expression',
  'iex',
  'Remove-Item',
]);

const SHELL_TOOLS = new Set(['Bash', 'PowerShell']);

/** The command a Bash/PowerShell rule's specifier starts with (`npm` in `npm run:*`); null when it matches anything. */
function leadingCommand(specifier: string | null): string | null {
  if (specifier === null) {
    return null;
  }
  const withoutWildcard = specifier
    .replace(/:\*$/, '')
    .replace(/\s*\*$/, '')
    .trim();
  if (withoutWildcard === '' || withoutWildcard === '*') {
    return null;
  }
  return withoutWildcard.split(/\s+/)[0] ?? null;
}

/** Flags `permissions.allow` rules that pre-approve any shell command, or a command that runs arbitrary code (PROPOSED_FIXES.md 6.1). */
export const chapAgy007PreapprovedShell: Check = {
  id: ID,
  title: TITLE,
  severity: 'critical',
  category: 'agency',
  owasp: OWASP,
  appliesToProfiles: ['claude-code'],
  detects:
    'Claude Code `permissions.allow` rules that let it run any shell command, or any invocation of an interpreter, downloader, or destructive command, without asking.',
  heuristic:
    'A bare `Bash`/`PowerShell` rule, or one whose pattern is only a wildcard (`Bash(*)`, `Bash(:*)`), is critical. A rule whose command is an interpreter or one that runs, fetches, deletes, or escalates (`sh`, `python`, `node`, `npx`, `curl`, `wget`, `rm`, `sudo`, `xargs`, ...), with a trailing wildcard, is high: `Bash(python:*)` approves `python -c "<anything>"`.',
  remediation: REMEDIATION,
  run(model) {
    return permissionRules(model, 'allow')
      .filter((rule) => SHELL_TOOLS.has(rule.tool))
      .flatMap((rule) => {
        const command = leadingCommand(rule.specifier);
        const unrestricted = command === null;
        if (!unrestricted && !RISKY_COMMANDS.has(command)) {
          return [];
        }
        return [
          {
            checkId: ID,
            title: TITLE,
            severity: unrestricted ? ('critical' as const) : ('high' as const),
            category: 'agency' as const,
            owasp: OWASP,
            message: unrestricted
              ? `The allow rule '${rule.rule}' (${rule.file.scope} settings) lets Claude Code run any ${rule.tool} command without asking.`
              : `The allow rule '${rule.rule}' (${rule.file.scope} settings) pre-approves '${command}', which can run, fetch, or delete anything, so it is nearly as broad as allowing every command.`,
            location: { filePath: rule.file.path, line: rule.line, detail: rule.rule },
            remediation: REMEDIATION,
          },
        ];
      });
  },
};
