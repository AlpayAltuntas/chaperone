import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SUP-004';
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
    "`curl`/`wget` piped into `sh`/`bash`, `sudo`, `apt-get install`, or `brew install`, found in `package.json`'s `preinstall`/`install`/`postinstall` scripts, any `*.sh` file, or any `README*` in the skill directory.",
  remediation:
    'Review the install script by hand; prefer a vetted, minimal setup with no piped-shell or sudo steps.',
  run(model) {
    const findings = [];
    for (const skill of model.skills) {
      for (const script of skill.installScripts.scripts) {
        findings.push({
          checkId: ID,
          title: TITLE,
          severity: 'medium' as const,
          category: 'supply-chain' as const,
          owasp: OWASP,
          message: `Skill '${skill.name}' install script contains a dangerous pattern (${script.dangerousPatterns.join(', ')}) in ${script.path}.`,
          location: { filePath: script.path, line: null, detail: skill.name },
          remediation:
            'Review the install script by hand; prefer a vetted, minimal setup with no piped-shell or sudo steps.',
        });
      }
    }
    return findings;
  },
};
