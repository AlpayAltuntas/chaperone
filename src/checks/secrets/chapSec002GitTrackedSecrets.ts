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
    if (isGitignored(model.git.configPathRelativeToGitRoot, model.git.gitignorePatterns)) {
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
