import type { Check } from '../../engine/types.js';

const ID = 'CHAP-AGY-004';
const TITLE = 'Broad network egress from a skill';
const OWASP = 'LLM08: Excessive Agency / LLM06';

/** Flags network-capable skills with no declared domain allowlist. */
export const chapAgy004BroadNetworkEgress: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'agency',
  owasp: OWASP,
  detects: 'Skills permitted to call arbitrary external endpoints.',
  heuristic:
    "The skill's source shows network capability (`fetch`, `http(s).request`, `axios`/`node-fetch`) and its manifest declares no non-empty `domainAllowlist` array (same manifest-convention caveat as CHAP-AGY-003).",
  remediation:
    'Allowlist the specific destination domain(s) the skill needs and log outbound calls.',
  run(model) {
    return model.skills
      .filter(
        (skill) =>
          skill.capabilities.networkAccess &&
          (skill.domainAllowlist === null || skill.domainAllowlist.length === 0),
      )
      .map((skill) => ({
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'agency',
        owasp: OWASP,
        message: `Skill '${skill.name}' can call arbitrary external endpoints — no domain allowlist is declared.`,
        location: { filePath: skill.manifestPath ?? skill.dir, line: null, detail: skill.name },
        remediation:
          'Allowlist the specific destination domain(s) this skill needs and log outbound calls.',
      }));
  },
};
