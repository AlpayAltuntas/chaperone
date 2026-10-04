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
    'The skill declares at least one runtime dependency with no lockfile alongside it. npm: a `package.json` `dependencies` entry and no `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`. Python (when there is no `package.json`): a `requirements.txt` or `pyproject.toml` dependency and no `poetry.lock`/`uv.lock`/`Pipfile.lock`/`pdm.lock`; a `requirements.txt` whose every entry has a `--hash=` counts as its own lockfile. A manifest with no dependencies has nothing to install, so it is not flagged.',
  remediation: 'Commit a lockfile alongside the manifest and enable integrity checks.',
  run(model) {
    return model.skills
      .filter(
        (skill) =>
          skill.dependencies.manifestPath !== null &&
          skill.dependencies.names.length > 0 &&
          skill.dependencies.lockfilePath === null,
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
