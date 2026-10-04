import type { Check } from '../../engine/types.js';
import { locateEvidence } from '../shared/skillEvidence.js';

const ID = 'CHAP-AGY-001';
const TITLE = 'Unrestricted shell execution';
const OWASP = 'LLM08: Excessive Agency';

/**
 * Flags skills whose source exposes a shell/exec/spawn capability
 * (child_process, exec/execSync, spawn/spawnSync). A command allowlist
 * isn't detected. A manifest-declared `confirmationRequired: true` (the
 * same field CHAP-AGY-003 honors) downgrades the finding to high rather
 * than silencing it: the gate is self-declared and Chaperone can't verify
 * it's enforced (PROPOSED_FIXES.md 2.9).
 */
export const chapAgy001UnrestrictedShell: Check = {
  id: ID,
  title: TITLE,
  severity: 'critical',
  severityNote: 'Critical (High when the skill declares `confirmationRequired: true`)',
  category: 'agency',
  owasp: OWASP,
  detects: 'Skills/plugins that can run arbitrary shell commands.',
  heuristic:
    "A skill's source contains a shell/exec/spawn capability: `child_process` (`exec`/`execFile`/`spawn`/`fork` and their sync forms), `execa`, `shelljs.exec`, `zx` `$`, `cross-spawn`, `node-pty`, `Bun.spawn`, or `new Deno.Command`. One level of aliasing (`const run = cp['exec']`), nested and template-literal member access, and inline `require(...)` are resolved. A command allowlist isn't detected, so any detected shell capability is treated as unrestricted. If the skill's manifest declares `confirmationRequired: true`, the finding is downgraded to High: the gate is self-declared and can't be verified statically.",
  remediation:
    'Constrain the skill to an explicit command allowlist, require confirmation for shell actions, or sandbox its execution.',
  run(model) {
    return model.skills
      .filter((skill) => skill.capabilities.shellExec)
      .map((skill) => {
        const gated = skill.confirmationRequired === true;
        const { location, related, seenAt } = locateEvidence(skill, 'shellExec');
        return {
          checkId: ID,
          title: TITLE,
          severity: gated ? ('high' as const) : ('critical' as const),
          category: 'agency' as const,
          owasp: OWASP,
          message: gated
            ? `Skill '${skill.name}' can execute arbitrary shell commands. Its manifest declares a confirmation gate, but no command allowlist was detected and Chaperone can't verify the gate is enforced.${seenAt}`
            : `Skill '${skill.name}' can execute arbitrary shell commands with no detected command allowlist or confirmation gate.${seenAt}`,
          location,
          ...related,
          remediation:
            'Constrain the skill to an explicit command allowlist, require confirmation for shell actions, or sandbox its execution.',
        };
      });
  },
};
