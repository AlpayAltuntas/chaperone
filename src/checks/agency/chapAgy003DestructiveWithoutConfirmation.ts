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
  detects:
    'Skills that can delete data, send messages, spend money, or otherwise act irreversibly with no human-in-the-loop gate.',
  heuristic:
    "The skill's source contains a destructive-action keyword as a standalone word (`delete`, `send`, `transfer`, `purchase`, `deploy`, `remove`, `pay`), and its manifest does not declare `confirmationRequired: true` (checked at the manifest's top level or nested under `capabilities`) — an invented-but-documented convention, no real manifest schema exists for these example agents (see DECISIONS.md).",
  remediation: 'Require explicit confirmation before this action runs (or add a dry-run mode).',
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
