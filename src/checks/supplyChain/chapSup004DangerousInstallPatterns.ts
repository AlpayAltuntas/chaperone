import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SUP-004';
const NPM_SCRIPT_PREFIX = 'package.json#';
const TITLE = 'Dangerous install pattern';
const OWASP = 'LLM05: Supply Chain';

/** Surfaces the dangerous install-script patterns discovery already detected (curl | bash, sudo, package-manager bootstraps). */
export const chapSup004DangerousInstallPatterns: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'supply-chain',
  owasp: OWASP,
  detects:
    'Skill install scripts/docs that pipe a remote script into a shell, use `sudo`, or bootstrap a system package manager.',
  heuristic:
    "A download executed by a shell: `curl`/`wget` piped into `sh`/`bash`/`zsh` (including `| sudo bash` and `| bash -s`), `bash <(curl …)`, PowerShell `iwr`/`irm … | iex`, or `base64 -d … | sh`; plus `sudo`. Searched in `package.json`'s `preinstall`/`install`/`postinstall`/`prepare` scripts (`prepare` runs on a git install), every `*.sh` file anywhere in the skill, and any top-level `README*`. `apt-get install`/`brew install` count only in install scripts and `*.sh` files, since a README recommending a package manager is normal.",
  remediation:
    'Review the install script by hand; prefer a vetted, minimal setup with no piped-shell or sudo steps.',
  run(model) {
    const findings = [];
    for (const skill of model.skills) {
      for (const script of skill.installScripts.scripts) {
        // An npm lifecycle script is reported by discovery as
        // `package.json#scripts.<name>`, which isn't a file path. Point at
        // the real package.json and keep the script name in `detail`, so
        // two scripts in one manifest stay distinct findings.
        const npmScript = script.path.startsWith(NPM_SCRIPT_PREFIX)
          ? script.path.slice(NPM_SCRIPT_PREFIX.length)
          : null;
        const location =
          npmScript !== null
            ? {
                filePath: skill.dependencies.manifestPath ?? skill.manifestPath ?? skill.dir,
                line: null,
                detail: `${skill.name} ${npmScript}`,
              }
            : { filePath: script.path, line: null, detail: skill.name };
        findings.push({
          checkId: ID,
          title: TITLE,
          severity: 'medium' as const,
          category: 'supply-chain' as const,
          owasp: OWASP,
          message: `Skill '${skill.name}' install script contains a dangerous pattern (${script.dangerousPatterns.join(', ')}) in ${script.path}.`,
          location,
          remediation:
            'Review the install script by hand; prefer a vetted, minimal setup with no piped-shell or sudo steps.',
        });
      }
    }
    return findings;
  },
};
