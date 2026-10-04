import type { Check } from '../../engine/types.js';
import type { Finding } from '../../model/types.js';
import { settingValue } from '../shared/claudeCode.js';

const ID = 'CHAP-AGY-006';
const TITLE = 'Claude Code runs every tool without asking';
const OWASP = 'LLM08: Excessive Agency';
const REMEDIATION =
  'Remove `permissions.defaultMode: "bypassPermissions"` and pre-approve only the specific commands the project needs with `permissions.allow` rules. To stop anyone entering the mode, set `permissions.disableBypassPermissionsMode`.';

/** Flags `permissions.defaultMode: "bypassPermissions"` in Claude Code settings (PROPOSED_FIXES.md 6.1). */
export const chapAgy006BypassPermissions: Check = {
  id: ID,
  title: TITLE,
  severity: 'critical',
  category: 'agency',
  owasp: OWASP,
  appliesToProfiles: ['claude-code'],
  detects:
    'Claude Code settings that start every session in `bypassPermissions` mode, where every tool call, including any shell command, runs without a permission prompt.',
  heuristic:
    '`permissions.defaultMode` is `"bypassPermissions"`. In user settings this applies to every project: critical. Current Claude Code (v2.1.257+) ignores the value in project and local settings, so there it is reported as low (it still applied on older versions, and it signals intent). `skipDangerousModePermissionPrompt: true` is mentioned when set.',
  remediation: REMEDIATION,
  run(model) {
    const findings: Finding[] = [];
    for (const file of model.claudeCodeSettings) {
      if (settingValue(file, ['permissions', 'defaultMode']) !== 'bypassPermissions') {
        continue;
      }
      const effective = file.scope === 'user';
      const skipPrompt = settingValue(file, ['skipDangerousModePermissionPrompt']) === true;
      findings.push({
        checkId: ID,
        title: TITLE,
        severity: effective ? 'critical' : 'low',
        category: 'agency',
        owasp: OWASP,
        message: effective
          ? `User settings start every Claude Code session in bypassPermissions mode: every tool call, including any shell command, runs without asking${skipPrompt ? ', and the confirmation dialog for the mode is skipped' : ''}.`
          : `${file.scope === 'local' ? 'Local' : 'Project'} settings set bypassPermissions mode. Current Claude Code ignores it in ${file.scope} settings, but older versions applied it, and a shared project file asks every teammate to run without prompts.`,
        location: {
          filePath: file.path,
          line: file.keyLines['permissions.defaultMode'] ?? null,
          detail: 'permissions.defaultMode',
        },
        remediation: REMEDIATION,
      });
    }
    return findings;
  },
};
