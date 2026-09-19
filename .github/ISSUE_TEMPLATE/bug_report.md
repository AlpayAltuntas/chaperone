---
name: Bug report
about: A check that's wrong (false positive/negative), a crash, or anything else not behaving as documented
title: ''
labels: bug
assignees: ''
---

<!--
Found a security vulnerability in Chaperone itself, or a false negative
that matters? Please use SECURITY.md instead of a public issue:
https://github.com/AlpayAltuntas/chaperone/security/advisories/new
-->

**Which check is this about?** (e.g. `CHAP-SEC-001`; run `chaperone checks`
if you're not sure of the ID, or leave blank if this isn't check-specific)

**Expected finding/behavior:**

**Actual finding/behavior:**

**A minimal config/skill snippet that reproduces it**, with any real
secrets/hostnames/paths replaced with obviously-fake placeholders (never
paste real credentials — see `test/fixtures/` for the convention this
repo's own fixtures use):

```yaml

```

**Chaperone version** (`chaperone version` or `npm ls @alpay_altuntas/chaperone`):

**Node.js version** (`node --version`) and **OS**:

**Anything else that might be relevant:**
