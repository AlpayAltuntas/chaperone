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
 *
 * Severity is `info`, not `high` (improvement_plan.md 1.15, mitigation
 * half): a signal this weak — "go run npm audit yourself" on literally
 * every skill with a package.json — shouldn't be able to trip
 * `--fail-on high` or meaningfully drag down the posture score on its
 * own. It's a reminder, not a finding Chaperone actually has confidence
 * in. Revisit once the real fix (an offline vulnerability database,
 * improvement_plan.md Phase 18) lands and this can go back to a severity
 * that reflects genuine confidence.
 */
export const chapSup003KnownVulnerableDependencies: Check = {
  id: ID,
  title: TITLE,
  severity: 'info',
  severityNote: 'Info (demoted from High)',
  category: 'supply-chain',
  owasp: OWASP,
  detects: 'Any skill dependency manifest, surfaced for manual review.',
  heuristic:
    "(Deliberately weak, v1.) Chaperone makes no outbound network calls (§14), so it cannot check dependencies against a live advisory database. This check simply fires on any skill with a `package.json` and points the user at `npm audit` — it fires on a hardened install exactly as readily as a vulnerable one. This is a documented v1 limitation, not a bug; see `test/checks/chapSup003.test.ts` and DECISIONS.md. Severity is `Info` rather than the category's usual weight specifically because of that weakness — a real vulnerability match would warrant `High` again (see `improvement_plan.md` Phase 18, the planned offline-vulnerability-database fix).",
  remediation:
    "Run npm audit (or your package manager's equivalent) inside the skill directory; update or remove vulnerable/unused dependencies.",
  run(model) {
    return model.skills
      .filter((skill) => skill.dependencies.manifestPath !== null)
      .map((skill) => ({
        checkId: ID,
        title: TITLE,
        severity: 'info',
        category: 'supply-chain',
        owasp: OWASP,
        message: `Skill '${skill.name}' has a dependency manifest Chaperone cannot check against a vulnerability database offline. Run 'npm audit' inside the skill directory to check for known-vulnerable dependencies.`,
        location: { filePath: skill.dependencies.manifestPath, line: null, detail: skill.name },
        remediation:
          "Run npm audit (or your package manager's equivalent) inside the skill directory; update or remove vulnerable/unused dependencies.",
      }));
  },
};
