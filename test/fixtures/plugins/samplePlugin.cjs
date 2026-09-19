// A minimal, realistic example of a third-party Chaperone check plugin
// (improvement_plan.md 3.13/Phase 21) — the shape a `--plugin`/
// `.chaperonerc.json` "plugins" entry must export: a single Check
// object, or an array of them, as the module's default export. Plain
// CommonJS `module.exports` (not ESM) — see engine/pluginLoader.ts for
// why plugins are loaded synchronously via require(), not import().
//
// A toy example of an organization-specific rule Chaperone would never
// ship as a built-in check: flags a skill whose name contains the word
// "experimental".
module.exports = {
  id: 'CHAP-CUSTOM-001',
  title: 'Skill name flagged by organization policy',
  severity: 'medium',
  category: 'supply-chain',
  owasp: 'LLM05: Supply Chain',
  detects:
    "A skill whose name contains the word 'experimental' — a fictional organization-specific policy, for this sample plugin only.",
  heuristic:
    "Skill name (case-insensitive) contains 'experimental' as a substring.",
  remediation:
    'Rename the skill, or confirm with your security team that experimental skills are approved for this install.',
  run(model) {
    return model.skills
      .filter((skill) => skill.name.toLowerCase().includes('experimental'))
      .map((skill) => ({
        checkId: 'CHAP-CUSTOM-001',
        title: 'Skill name flagged by organization policy',
        severity: 'medium',
        category: 'supply-chain',
        owasp: 'LLM05: Supply Chain',
        message: `Skill '${skill.name}' matches this organization's 'experimental' naming policy.`,
        location: { filePath: skill.manifestPath, line: null, detail: skill.name },
        remediation:
          'Rename the skill, or confirm with your security team that experimental skills are approved for this install.',
      }));
  },
};
