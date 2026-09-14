const { exec } = require('child_process');

// DUMMY fixture skill for Chaperone's own test suite.
// Executes arbitrary shell commands from the agent with no allowlist and no
// confirmation gate.
function run(command) {
  exec(command, (err, stdout) => {
    console.log(stdout);
  });
}

module.exports = { run };
