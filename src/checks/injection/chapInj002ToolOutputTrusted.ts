import type { Check } from '../../engine/types.js';

const ID = 'CHAP-INJ-002';
const TITLE = 'Tool output treated as trusted';
const OWASP = 'LLM02: Insecure Output Handling';

/**
 * A skill that both ingests external/tool data (network or filesystem
 * access) AND can execute shell commands is a plausible static proxy for
 * "a tool's output can trigger another tool with no validation step" —
 * Chaperone has no real data-flow analysis, so this flags the *shape* of a
 * chain rather than confirming one exists. Documented limitation, not a
 * confirmed injection path.
 */
export const chapInj002ToolOutputTrusted: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'injection',
  owasp: OWASP,
  run(model) {
    return model.skills
      .filter(
        (skill) =>
          skill.capabilities.shellExec &&
          (skill.capabilities.networkAccess || skill.capabilities.fileSystemAccess),
      )
      .map((skill) => ({
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'injection',
        owasp: OWASP,
        message: `Skill '${skill.name}' both ingests external data (${skill.capabilities.networkAccess ? 'network' : 'filesystem'}) and can execute shell commands, with no detected validation step in between.`,
        location: { filePath: skill.manifestPath ?? skill.dir, line: null, detail: skill.name },
        remediation:
          "Validate/escape a tool's output before it can drive another tool; never auto-execute model or tool output.",
      }));
  },
};
