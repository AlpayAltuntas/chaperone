import type { Check } from '../../engine/types.js';
import { settingValue } from '../shared/claudeCode.js';

const ID = 'CHAP-SUP-008';
const TITLE = 'Project MCP servers approved without review';
const OWASP = 'LLM05: Supply Chain';
const REMEDIATION =
  'Remove `enableAllProjectMcpServers` and approve servers by name with `enabledMcpjsonServers`, after reviewing each one.';

/** Flags `enableAllProjectMcpServers: true` (PROPOSED_FIXES.md 6.1). */
export const chapSup008AutoApprovedMcpServers: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'supply-chain',
  owasp: OWASP,
  appliesToProfiles: ['claude-code'],
  detects:
    "Claude Code configured to start every server in a project's `.mcp.json` without asking: any repository it's opened in can launch its own processes.",
  heuristic:
    '`enableAllProjectMcpServers` is `true` in any settings file. In user settings it applies to every repository you open, including ones you just cloned.',
  remediation: REMEDIATION,
  run(model) {
    return model.claudeCodeSettings
      .filter((file) => settingValue(file, ['enableAllProjectMcpServers']) === true)
      .map((file) => ({
        checkId: ID,
        title: TITLE,
        severity: 'high' as const,
        category: 'supply-chain' as const,
        owasp: OWASP,
        message:
          file.scope === 'user'
            ? "User settings approve every project's .mcp.json servers without asking, so any repository opened in Claude Code, including a freshly cloned one, can start its own MCP server processes."
            : `${file.scope === 'local' ? 'Local' : 'Project'} settings approve every server in this project's .mcp.json without asking, so a change to that file starts new processes with no review.`,
        location: {
          filePath: file.path,
          line: file.keyLines['enableAllProjectMcpServers'] ?? null,
          detail: 'enableAllProjectMcpServers',
        },
        remediation: REMEDIATION,
      }));
  },
};
