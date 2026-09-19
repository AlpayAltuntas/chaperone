const fs = require('fs');

// DUMMY fixture skill for Chaperone's own test suite.
// Writes files at any path the caller supplies (no scoping to a fixed
// workspace directory) and can permanently erase one with no
// confirmation gate. (Detection of the destructive action below comes
// purely from the real `deleteFile` function name, not this comment —
// see improvement_plan.md 1.1 / DECISIONS.md, Phase 10.)
function writeAnywhere(targetPath, content) {
  fs.writeFileSync(targetPath, content, 'utf8');
}

function deleteFile(targetPath) {
  fs.unlink(targetPath, () => {});
}

module.exports = { writeAnywhere, deleteFile };
