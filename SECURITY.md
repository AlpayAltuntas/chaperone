# Security Policy

Chaperone is a security tool, which means reports about it carry a bit
more weight than the average bug report. Two kinds of issue are in scope
here — please report both the same way:

1. **A bug in Chaperone itself** — anything that would violate its own
   guardrails (see the README's [Security & ethics](README.md#security--ethics)
   section): `chaperone scan` writing to, modifying, or deleting anything
   in a scanned installation, or making an outbound network call; a real
   secret value leaking into console/JSON/SARIF/markdown/gha/html output
   instead of being masked; `chaperone fix` writing a change without
   `--write --dry-run` having been passed; `chaperone check-update`
   making a network call anywhere outside that one explicit, opt-in
   command; or any other way the tool could act on, or expose, more than
   it should. (`chaperone fix --write --dry-run` and `chaperone
check-update` are the two narrow, documented exceptions to
   read-only/no-network — see the README section above — not bugs in
   themselves.)
2. **A false negative that matters** — a check silently failing to catch
   something it's designed to catch (as opposed to a merely annoying
   false positive). For a scanner, a missed finding is arguably a
   security-relevant report in its own right, not just a correctness bug.
   If you're not sure whether something rises to this level, report it
   anyway — worst case, it gets triaged as a regular bug.

Ordinary bugs, false positives, and feature requests that don't fit
either category above should go to the
[issue tracker](https://github.com/AlpayAltuntas/chaperone/issues)
instead, using the bug report template.

## Reporting a vulnerability

**Preferred:** use GitHub's private vulnerability reporting —
[open a draft security advisory](https://github.com/AlpayAltuntas/chaperone/security/advisories/new)
for this repository. This keeps the report private until a fix is ready,
rather than disclosing it in a public issue.

**Alternative:** email `alpaycanaltuntas@gmail.com` with a description of
the issue. If reporting a false negative, include a redacted/synthetic
example (no real secrets, credentials, or third-party data) that
reproduces it — the same convention this repo's own fixtures already
follow (see `test/fixtures/`).

## What to expect

This is currently a one-maintainer project, so please treat "expected
response time" as a best effort, not an SLA:

- An initial acknowledgment within a few days.
- A fix or a clear mitigation plan communicated before any public
  disclosure, once the report is confirmed.
- Credit in `CHANGELOG.md` for the fix, if you'd like it (just say so in
  your report — otherwise reports are kept confidential by default).

## Supported versions

Only the latest published version on npm
([`@alpay_altuntas/chaperone`](https://www.npmjs.com/package/@alpay_altuntas/chaperone))
is supported. There's no backport policy yet — the project is too young
for one.
