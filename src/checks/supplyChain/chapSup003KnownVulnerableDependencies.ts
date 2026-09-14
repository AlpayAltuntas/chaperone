import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SUP-003';
const TITLE = 'Dependency manifest not checked for known vulnerabilities';
const OWASP = 'LLM05: Supply Chain';

/**
 * v1 heuristic, per instruction.md §7: Chaperone makes no outbound network
 * calls (§14), so it cannot check dependencies against a live advisory
 * database. It surfaces every dependency manifest it finds instead, and
 * tells the user to run `npm audit` themselves — a deliberately weak,
 * honestly-labeled signal rather than a real vulnerability match. This
 * check fires on any skill with a manifest, in both a vulnerable and a
 * hardened install alike.
 */
export const chapSup003KnownVulnerableDependencies: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'supply-chain',
  owasp: OWASP,
  run(model) {
    return model.skills
      .filter((skill) => skill.dependencies.manifestPath !== null)
      .map((skill) => ({
        checkId: ID,
        title: TITLE,
        severity: 'high',
        category: 'supply-chain',
        owasp: OWASP,
        message: `Skill '${skill.name}' has a dependency manifest Chaperone cannot check against a vulnerability database offline. Run 'npm audit' inside the skill directory to check for known-vulnerable dependencies.`,
        location: { filePath: skill.dependencies.manifestPath, line: null, detail: skill.name },
        remediation:
          "Run npm audit (or your package manager's equivalent) inside the skill directory; update or remove vulnerable/unused dependencies.",
      }));
  },
};
