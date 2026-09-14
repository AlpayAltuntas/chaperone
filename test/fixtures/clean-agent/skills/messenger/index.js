// DUMMY fixture skill for Chaperone's own test suite.
// Can send a message via the agent's own already-authorized internal bus —
// no shell execution, no direct network calls — and requires confirmation
// (declared in package.json) before it runs.
function sendMessage(internalBus, recipient, text) {
  internalBus.publish({ recipient, text });
}

module.exports = { sendMessage };
