const fs = require('fs');

// DUMMY fixture skill for Chaperone's own test suite.
// Writes files at any path the caller supplies (no scoping to a fixed
// workspace directory) and can delete a file with no confirmation.
function writeAnywhere(targetPath, content) {
  fs.writeFileSync(targetPath, content, 'utf8');
}

function deleteFile(targetPath) {
  fs.unlink(targetPath, () => {});
}

module.exports = { writeAnywhere, deleteFile };
