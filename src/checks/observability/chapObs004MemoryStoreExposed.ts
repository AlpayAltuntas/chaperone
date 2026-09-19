import path from 'node:path';
import type { Check } from '../../engine/types.js';
import { isGitignored } from '../shared/gitignoreMatch.js';

const ID = 'CHAP-OBS-004';
const TITLE = 'Persistent memory/state store exposed';
const OWASP = 'LLM06: Sensitive Information Disclosure';

/**
 * Mirrors CHAP-SEC-002/CHAP-SEC-003's git-tracking and permission checks,
 * applied to the persistent memory/state directory (instruction.md §2's
 * fifth discoverable artifact, previously undiscovered — see
 * improvement_plan.md 1.7/2.8) instead of the config file. No content
 * inside the directory is ever read; conversation memory accumulates
 * sensitive material over time and deserves the same exposure scrutiny
 * config.yaml already gets, without Chaperone needing to look inside it.
 */
export const chapObs004MemoryStoreExposed: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'observability',
  owasp: OWASP,
  run(model) {
    if (!model.memory.present || model.memory.dir === null) {
      return [];
    }

    const fact = model.permissions.find((p) => p.path === model.memory.dir);
    if (fact === undefined || !fact.exists) {
      return [];
    }

    const reasons: string[] = [];

    if (fact.groupOrOtherReadable === true) {
      const modeOctal = fact.mode !== null ? fact.mode.toString(8).padStart(3, '0') : 'unknown';
      reasons.push(`it is readable by group or other (mode ${modeOctal})`);
    }

    if (model.git.hasAncestorGitDir && model.git.gitRootPath !== null) {
      const relative = path.relative(model.git.gitRootPath, model.memory.dir);
      if (!isGitignored(relative, model.git.gitignorePatterns)) {
        reasons.push(
          `it sits inside a git repository (${model.git.gitRootPath}) without being covered by its .gitignore`,
        );
      }
    }

    if (reasons.length === 0) {
      return [];
    }

    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'observability',
        owasp: OWASP,
        message: `The persistent memory/state store is exposed: ${reasons.join('; ')}.`,
        location: { filePath: model.memory.dir, line: null, detail: 'memory_dir' },
        remediation:
          'Restrict the memory/state directory to owner-only access (chmod 700) and add it to .gitignore — it can accumulate sensitive conversational content over time.',
      },
    ];
  },
};
