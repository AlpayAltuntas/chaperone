import type { Check } from '../../engine/types.js';
import { matchDangerousPatterns } from '../../discovery/skillsScanner.js';
import { settingsCommands } from '../shared/claudeCode.js';

const ID = 'CHAP-SUP-009';
const TITLE = 'Claude Code hook runs downloaded code';
const OWASP = 'LLM05: Supply Chain';
const REMEDIATION =
  'Vendor the script into the repository (and review it) instead of piping a download into a shell, and avoid `sudo` in commands Claude Code runs automatically.';

/** Flags hook and helper commands in Claude Code settings that pipe a download into a shell or use sudo (PROPOSED_FIXES.md 6.1). */
export const chapSup009DangerousSettingsCommand: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'supply-chain',
  owasp: OWASP,
  appliesToProfiles: ['claude-code'],
  detects:
    'A command Claude Code runs on its own (a hook, `statusLine`, `fileSuggestion`, or `apiKeyHelper`) that executes code fetched at run time, so whoever controls that URL controls your machine on every trigger.',
  heuristic:
    'The same patterns as CHAP-SUP-004: `curl`/`wget` piped into a shell, `bash <(curl …)`, `iwr … | iex`, `base64 -d … | sh`, `sudo`, and package installs.',
  remediation: REMEDIATION,
  run(model) {
    return model.claudeCodeSettings.flatMap((file) =>
      settingsCommands(file).flatMap((entry) => {
        const patterns = matchDangerousPatterns(entry.command, true);
        return patterns.length === 0
          ? []
          : [
              {
                checkId: ID,
                title: TITLE,
                severity: 'high' as const,
                category: 'supply-chain' as const,
                owasp: OWASP,
                message: `'${entry.keyPath}' (${file.scope} settings) runs a dangerous command pattern (${patterns.join(', ')}) every time it triggers.`,
                location: { filePath: file.path, line: entry.line, detail: entry.keyPath },
                remediation: REMEDIATION,
              },
            ];
      }),
    );
  },
};
