// DUMMY fixture skill for Chaperone's own test suite.
// Can dispatch a message via the agent's own already-authorized internal
// bus — no shell execution, no direct network calls — and requires
// confirmation (declared in package.json) before it runs. (Detection of
// the destructive action below comes purely from the real
// `sendMessage` function name, not this comment — see
// improvement_plan.md 1.1 / DECISIONS.md, Phase 10.)
function sendMessage(internalBus, recipient, text) {
  internalBus.publish({ recipient, text });
}

module.exports = { sendMessage };
