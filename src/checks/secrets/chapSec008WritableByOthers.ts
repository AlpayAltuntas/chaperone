import type { Check } from '../../engine/types.js';
import type { PermissionRole } from '../../model/types.js';

const ID = 'CHAP-SEC-008';
const TITLE = 'Agent files writable by other users';
const OWASP = 'LLM05: Supply Chain';

// Paths whose contents decide what the agent does: its config, the
// install root, every skill (code the agent runs with its own
// privileges), and its memory (read back into prompts, so writable memory
// is persistent prompt injection).
const ROLE_LABEL: Partial<Record<PermissionRole, string>> = {
  config: 'config file',
  'target-root': 'install directory',
  'skills-dir': 'skills directory',
  'skill-dir': 'skill directory',
  'memory-dir': 'memory directory',
};

const ROLE_IMPACT: Partial<Record<PermissionRole, string>> = {
  config: 'can rewrite the agent configuration',
  'target-root': 'can add or replace files in the install, including its config',
  'skills-dir': 'can plant a new skill that the agent will load and run',
  'skill-dir': "can modify this skill's code, which the agent runs with its own privileges",
  'memory-dir': 'can poison the agent memory, a persistent prompt-injection vector',
};

/** Flags agent files and directories that group or other users can write (PROPOSED_FIXES.md 3.6). */
export const chapSec008WritableByOthers: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'secrets',
  owasp: OWASP,
  detects:
    'The config file, install directory, skills directory, any skill directory, or the memory directory being writable by users other than the owner.',
  heuristic:
    "POSIX mode with a group or other write bit (`0o022`) set on any of those paths. A writable skills directory lets any local user or process plant code that the agent runs with its own privileges (a local privilege escalation); writable memory lets them inject persistent instructions. Meaningful on macOS/Linux only: on Windows, Node's reported mode doesn't reflect other users' access, so no finding is reported there.",
  remediation:
    'Remove group/other write access, e.g. `chmod go-w <path>` (`chmod -R go-w` for a skills directory), and make sure the agent runs as a dedicated user that owns its files.',
  run(model) {
    return model.permissions
      .filter((fact) => ROLE_LABEL[fact.role] !== undefined && fact.groupOrOtherWritable === true)
      .map((fact) => {
        const modeOctal = fact.mode !== null ? fact.mode.toString(8).padStart(3, '0') : 'unknown';
        const label = ROLE_LABEL[fact.role] ?? fact.role;
        const impact = ROLE_IMPACT[fact.role] ?? 'can modify it';
        return {
          checkId: ID,
          title: TITLE,
          severity: 'high' as const,
          category: 'secrets' as const,
          owasp: OWASP,
          message: `The ${label} is writable by group or other (mode ${modeOctal}), so any local user or process ${impact}.`,
          location: { filePath: fact.path, line: null, detail: `${fact.role} mode ${modeOctal}` },
          remediation: `Remove group/other write access: \`chmod ${fact.role === 'skills-dir' ? '-R ' : ''}go-w ${fact.path}\`.`,
        };
      });
  },
};
