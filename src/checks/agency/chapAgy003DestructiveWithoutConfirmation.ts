import type { Check } from '../../engine/types.js';

const ID = 'CHAP-AGY-003';
const TITLE = 'Destructive action without confirmation';
const OWASP = 'LLM08: Excessive Agency';

/** Flags skills whose source shows a destructive-action keyword (delete, send, transfer, ...) with no declared confirmation gate. */
export const chapAgy003DestructiveWithoutConfirmation: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'agency',
  owasp: OWASP,
  run(model) {
    return model.skills
      .filter(
        (skill) =>
          skill.capabilities.destructiveKeywords.length > 0 && skill.confirmationRequired !== true,
      )
      .map((skill) => ({
        checkId: ID,
        title: TITLE,
        severity: 'high',
        category: 'agency',
        owasp: OWASP,
        message: `Skill '${skill.name}' can perform a destructive/irreversible action (${skill.capabilities.destructiveKeywords.join(', ')}) with no declared confirmation gate.`,
        location: { filePath: skill.manifestPath ?? skill.dir, line: null, detail: skill.name },
        remediation:
          'Require explicit confirmation before this action runs (or add a dry-run mode) before treating it as safe to invoke.',
      }));
  },
};
