import type { Check } from '../../engine/types.js';
import { isGitignored } from '../shared/gitignoreMatch.js';

const ID = 'CHAP-SEC-002';
const TITLE = 'Secrets in a git-tracked path';
const OWASP = 'LLM06: Sensitive Information Disclosure';

/**
 * Flags a config file that holds a literal secret and sits inside a git
 * repo without being covered by that repo's root .gitignore. Only fires
 * when there's an actual literal secret to protect — a secret-free config
 * being git-tracked isn't a secrets-hygiene issue.
 */
export const chapSec002GitTrackedSecrets: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'secrets',
  owasp: OWASP,
  detects:
    "A config file holding a literal secret that sits inside a git repository without being covered by that repo's `.gitignore`.",
  heuristic:
    "An ancestor `.git` directory exists above the config file (discovery-detected), the config holds at least one literal secret (see CHAP-SEC-001), and the config's path relative to the repo root doesn't match any pattern in the repo-root or a nested `.gitignore` between the git root and the scanned target. Matching uses the `ignore` npm package (real gitignore semantics, including `**` and nested `.gitignore` files); see `checks/shared/gitignoreMatch.ts`. Known gap, not solved: `.git/info/exclude` and a user's global `core.excludesFile` aren't read, and \"not gitignored\" isn't the same as \"actually tracked\" (see DECISIONS.md).",
  remediation:
    'Add the config/secret file to .gitignore, and rotate any key that may already have been committed.',
  run(model) {
    if (
      model.config.path === null ||
      !model.git.hasAncestorGitDir ||
      model.git.configPathRelativeToGitRoot === null
    ) {
      return [];
    }
    const hasLiteralSecret = model.config.secretFields.some(
      (field) => !field.looksLikeEnvReference,
    );
    if (!hasLiteralSecret) {
      return [];
    }
    if (isGitignored(model.git.configPathRelativeToGitRoot, model.git.gitignoreFiles)) {
      return [];
    }

    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'high',
        category: 'secrets',
        owasp: OWASP,
        message: `The config file holds a literal secret and sits inside a git repository (${model.git.gitRootPath ?? 'unknown root'}) without being covered by its .gitignore.`,
        location: {
          filePath: model.config.path,
          line: null,
          detail: model.git.configPathRelativeToGitRoot,
        },
        remediation:
          'Add the config/secret file to .gitignore, and rotate any key that may already have been committed.',
      },
    ];
  },
};
