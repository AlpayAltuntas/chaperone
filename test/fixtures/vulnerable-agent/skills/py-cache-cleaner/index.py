import subprocess

# DUMMY fixture skill for Chaperone's own test suite.
# Runs a shell command to delete old cache files with no allowlist and no
# confirmation gate.


def clear_cache(days_old):
    subprocess.run(["find", "/tmp/cache", "-mtime", f"+{days_old}", "-delete"])
