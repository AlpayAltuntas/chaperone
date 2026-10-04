// An ES-module plugin (PROPOSED_FIXES.md 4.4): loaded through require(esm),
// which Node supports from 22.12, Chaperone's floor.
export default {
  id: 'CHAP-ESM-001',
  title: 'ESM plugin check',
  severity: 'low',
  category: 'supply-chain',
  owasp: 'LLM05: Supply Chain',
  detects: 'Nothing real; proves an ESM plugin loads.',
  heuristic: 'Reports one finding per skill.',
  remediation: 'None.',
  run(model) {
    return model.skills.map((skill) => ({
      checkId: 'CHAP-ESM-001',
      title: 'ESM plugin check',
      severity: 'low',
      category: 'supply-chain',
      owasp: 'LLM05: Supply Chain',
      message: `ESM plugin saw '${skill.name}'.`,
      location: { filePath: skill.dir, line: null, detail: skill.name },
      remediation: 'None.',
    }));
  },
};
