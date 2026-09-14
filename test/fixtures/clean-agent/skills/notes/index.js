const fs = require('fs');
const path = require('path');

// DUMMY fixture skill for Chaperone's own test suite.
// Reads and writes notes only inside its own scoped workspace directory —
// no shell execution, no network access.
const WORKSPACE = path.join(__dirname, 'workspace');

function writeNote(name, content) {
  fs.writeFileSync(path.join(WORKSPACE, name), content, 'utf8');
}

module.exports = { writeNote };
