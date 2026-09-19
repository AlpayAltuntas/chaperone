import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SUP-005';
const TITLE = 'Obfuscated or dynamically-evaluated code';
const OWASP = 'LLM05: Supply Chain';

/**
 * Flags a skill using eval()/Function() to run dynamically-constructed
 * code — a strong backdoor/malware smell independent of what's actually
 * being hidden, and a real hallmark of supply-chain attacks in the npm
 * ecosystem (improvement_plan.md 2.6). Unlocked by the AST work in
 * Phase 10 — astCapabilities.ts flags any eval/Function use
 * unconditionally, which already covers a decode-then-execute chain
 * like `eval(atob(payload))` as a special case (it's just a call whose
 * argument happens to itself be a call).
 */
export const chapSup005ObfuscatedCode: Check = {
  id: ID,
  title: TITLE,
  severity: 'critical',
  category: 'supply-chain',
  owasp: OWASP,
  detects:
    'A skill using eval(), the Function constructor, or a decode-then-execute chain (e.g. eval(atob(payload))) to run dynamically-constructed code.',
  heuristic:
    "Any call to the `eval`/`Function` globals (bare, or `new Function(...)`) in a skill's source. Flagged unconditionally regardless of what's being evaluated — a real backdoor and a benign use are equally invisible to static review once code is constructed/evaluated at runtime, so there's no confident way to distinguish them from source alone.",
  remediation:
    'Avoid dynamic code evaluation entirely. If genuinely needed, review the exact string being evaluated by hand and vendor/pin it rather than constructing or fetching it at runtime.',
  run(model) {
    return model.skills
      .filter((skill) => skill.capabilities.dynamicEval)
      .map((skill) => ({
        checkId: ID,
        title: TITLE,
        severity: 'critical' as const,
        category: 'supply-chain' as const,
        owasp: OWASP,
        message: `Skill '${skill.name}' uses eval()/Function() to run dynamically-constructed code — a common way to hide a malicious payload from static review.`,
        location: { filePath: skill.manifestPath ?? skill.dir, line: null, detail: skill.name },
        remediation:
          'Avoid dynamic code evaluation entirely; if truly needed, review the exact string being evaluated by hand and vendor/pin it rather than constructing it at runtime.',
      }));
  },
};
