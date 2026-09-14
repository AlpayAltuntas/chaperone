import type { Check } from '../../engine/types.js';

const ID = 'CHAP-AGY-001';
const TITLE = 'Unrestricted shell execution';
const OWASP = 'LLM08: Excessive Agency';

/**
 * Flags skills whose source exposes a shell/exec/spawn capability
 * (child_process, exec/execSync, spawn/spawnSync). v1's Skill model does
 * not yet detect a command allowlist or confirmation gate (see
 * DECISIONS.md, Phase 1 note on deferring that field until a check needs
 * it), so any detected shell capability is treated as unrestricted.
 */
export const chapAgy001UnrestrictedShell: Check = {
  id: ID,
  title: TITLE,
  severity: 'critical',
  category: 'agency',
  owasp: OWASP,
  run(model) {
    return model.skills
      .filter((skill) => skill.capabilities.shellExec)
      .map((skill) => ({
        checkId: ID,
        title: TITLE,
        severity: 'critical',
        category: 'agency',
        owasp: OWASP,
        message: `Skill '${skill.name}' can execute arbitrary shell commands with no detected command allowlist or confirmation gate.`,
        location: { filePath: skill.manifestPath ?? skill.dir, line: null, detail: skill.name },
        remediation:
          'Constrain the skill to an explicit command allowlist, require confirmation for shell actions, or sandbox its execution.',
      }));
  },
};
