// A deliberately broken plugin fixture — missing required Check fields
// and no run() function — for testing loadPlugin's validation error
// path (improvement_plan.md 3.13/Phase 21).
module.exports = {
  id: 'CHAP-CUSTOM-BROKEN',
  title: 'Missing everything else',
};
