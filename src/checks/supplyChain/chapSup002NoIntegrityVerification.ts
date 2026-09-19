import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SUP-002';
const TITLE = 'No integrity verification for skill dependencies';
const OWASP = 'LLM05: Supply Chain';

/** Flags skills that declare dependencies (a package.json) with no lockfile committed alongside it. */
export const chapSup002NoIntegrityVerification: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'supply-chain',
  owasp: OWASP,
  detects: 'Skill dependencies installed with no lockfile.',
  heuristic:
    'The skill has a `package.json` but no `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` alongside it.',
  remediation: 'Commit a lockfile alongside the manifest and enable integrity checks.',
  run(model) {
    return model.skills
      .filter(
        (skill) =>
          skill.dependencies.manifestPath !== null && skill.dependencies.lockfilePath === null,
      )
      .map((skill) => ({
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'supply-chain',
        owasp: OWASP,
        message: `Skill '${skill.name}' declares dependencies but has no lockfile, so installs aren't hash-verified or reproducible.`,
        location: { filePath: skill.dependencies.manifestPath, line: null, detail: skill.name },
        remediation:
          'Commit a lockfile (package-lock.json/yarn.lock/pnpm-lock.yaml) alongside the manifest and enable integrity checks.',
      }));
  },
};
