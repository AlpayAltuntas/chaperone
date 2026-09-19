import path from 'node:path';
import type { Check } from '../../engine/types.js';
import { isGitignored } from '../shared/gitignoreMatch.js';

const ID = 'CHAP-SEC-006';
const TITLE = 'Sidecar secret file exposed';
const OWASP = 'LLM06: Sensitive Information Disclosure';

/**
 * Applies the same two checks CHAP-SEC-002/CHAP-SEC-003 apply to the main
 * config — git-tracked-and-not-gitignored, and group/other-readable
 * permissions — to sidecar secret files (.env, secrets.yaml, secrets.json)
 * discovered alongside it (improvement_plan.md 1.6/2.2). Only fires per
 * file when it holds at least one literal secret; a reference-only or
 * empty sidecar file isn't a hygiene issue.
 */
export const chapSec006SidecarSecretFileExposed: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'secrets',
  owasp: OWASP,
  detects:
    "A sidecar secret file (`.env`, `.env.local`, `secrets.yaml`, `secrets.yml`, `secrets.json`) discovered alongside the main config, holding a literal secret that's either git-tracked and not gitignored, or readable by group/other.",
  heuristic:
    "Applies the exact same two checks CHAP-SEC-002/CHAP-SEC-003 apply to the main config file, to each discovered sidecar file instead: the file holds at least one literal (non-env-reference) secret field (masked the same way `config.yaml` is — see `discovery/configParser.ts`/`discovery/sidecarSecrets.ts`), and either its path relative to an ancestor git root isn't covered by the repo's `.gitignore`, or its POSIX mode is broader than `0600`. Both reasons are reported together in one finding when both hold.",
  remediation:
    'Add the file to .gitignore, rotate any key that may already have been committed, and restrict it to owner-only access (chmod 600).',
  run(model) {
    const findings = [];

    for (const file of model.sidecarSecretFiles) {
      const hasLiteralSecret = file.secretFields.some((field) => !field.looksLikeEnvReference);
      if (!hasLiteralSecret) {
        continue;
      }

      const reasons: string[] = [];

      if (model.git.hasAncestorGitDir && model.git.gitRootPath !== null) {
        const relative = path.relative(model.git.gitRootPath, file.path);
        if (!isGitignored(relative, model.git.gitignoreFiles)) {
          reasons.push(
            `it sits inside a git repository (${model.git.gitRootPath}) without being covered by its .gitignore`,
          );
        }
      }

      const fact = model.permissions.find((p) => p.path === file.path);
      if (fact !== undefined && fact.exists && fact.groupOrOtherReadable === true) {
        const modeOctal = fact.mode !== null ? fact.mode.toString(8).padStart(3, '0') : 'unknown';
        reasons.push(`it is readable by group or other (mode ${modeOctal})`);
      }

      if (reasons.length === 0) {
        continue;
      }

      findings.push({
        checkId: ID,
        title: TITLE,
        severity: 'high' as const,
        category: 'secrets' as const,
        owasp: OWASP,
        message: `Sidecar secret file '${path.basename(file.path)}' holds a literal secret and ${reasons.join('; ')}.`,
        location: { filePath: file.path, line: null, detail: file.format },
        remediation:
          'Add the file to .gitignore, rotate any key that may already have been committed, and restrict it to owner-only access (chmod 600).',
      });
    }

    return findings;
  },
};
