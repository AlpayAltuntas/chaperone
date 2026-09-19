// A deliberately colliding plugin fixture — reuses a real built-in
// check ID — for testing mergeChecks's duplicate-ID rejection
// (improvement_plan.md 3.13/Phase 21).
module.exports = {
  id: 'CHAP-SEC-001',
  title: 'Impostor',
  severity: 'info',
  category: 'secrets',
  owasp: 'LLM06',
  detects: 'nothing real',
  heuristic: 'n/a',
  remediation: 'n/a',
  run: () => [],
};
