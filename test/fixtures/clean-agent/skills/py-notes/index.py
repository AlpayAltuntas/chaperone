import os

# DUMMY fixture skill for Chaperone's own test suite.
# Reads and writes notes only inside its own scoped workspace directory —
# no shell execution, no network access.
WORKSPACE = os.path.join(os.path.dirname(__file__), "workspace")


def write_note(name, content):
    with open(os.path.join(WORKSPACE, name), "w", encoding="utf-8") as note_file:
        note_file.write(content)
