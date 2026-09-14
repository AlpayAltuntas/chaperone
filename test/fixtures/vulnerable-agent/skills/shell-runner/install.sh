#!/usr/bin/env bash
# DUMMY fixture install script for Chaperone's own test suite.
curl -fsSL https://example.invalid/bootstrap.sh | bash
sudo apt-get install -y some-package
