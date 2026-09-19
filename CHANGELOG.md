# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Versioning policy:** a new check landing, or an existing check's
severity changing, is treated as a semver **minor** bump at minimum —
either can change `--fail-on` exit-code behavior for an existing CI
pipeline, even though it isn't a breaking API change in the usual sense.

## [Unreleased]

### Fixed

- `CHAP-NET-001` no longer false-positives a critical finding on a
  gateway bound to any loopback address other than the exact literal
  `127.0.0.1` — the entire `127.0.0.0/8` block, and IPv6 loopback written
  in expanded form (`0:0:0:0:0:0:0:1`), are now correctly recognized as
  safe.
- Config fields named `private_key`, `ssh_key`, `encryption_key`, and
  other `*_key` names that aren't literally `api_key` are now correctly
  detected and masked as secrets — previously invisible to every secrets
  check.
- A config field merely _containing_ "token"/"secret"/etc. as a substring
  (e.g. `tokenizer_model`) is no longer incorrectly masked/flagged as a
  literal secret.
- `~`/`~/...` paths in config (`logging.path`, `skills_dir`) now expand
  to the real home directory instead of being resolved as a literal `~`
  subdirectory that silently doesn't exist.
- Bash/docker-compose-style default-value env references
  (`${VAR:-default}`, `${VAR:=default}`, `${VAR:?message}`,
  `${VAR:+alt}`) are now correctly recognized as indirect references
  rather than being masked and flagged as literal secrets.
- Untrusted skill manifest fields (`name`, `author`) are now sanitized of
  control characters and ANSI escape sequences before entering the model,
  closing a terminal-injection vector in console output.
- An unexpected error during a scan (as opposed to findings meeting
  `--fail-on`) now exits with a distinct code (`2`) instead of the same
  code (`1`) findings use, so CI can tell the two apart.

### Changed

- `CHAP-SUP-003` severity demoted from `High` to `Info`, pending a real
  offline-vulnerability-database fix (see `improvement_plan.md` Phase
  18). Its v1 heuristic fires on any skill with a `package.json`
  regardless of actual risk; at `High` it could trip `--fail-on high` or
  drag down a genuinely hardened install's posture score on nothing more
  than "you have a dependency manifest." This is a deliberate deviation
  from `instruction.md` §7's originally stated severity for this check.

## [0.1.0] - 2026-09-16

Initial public release, as [`@alpay_altuntas/chaperone`](https://www.npmjs.com/package/@alpay_altuntas/chaperone).

### Added

- 22 security checks across 6 categories (secrets & credential hygiene,
  excessive agency & permissions, supply chain & skill provenance,
  prompt-injection surface, exposure & network posture, observability &
  recoverability), each mapped to an OWASP LLM Top 10 category with a
  documented heuristic and true-positive/true-negative test fixtures.
- `chaperone scan [path]` — discovers and audits a self-hosted personal
  AI agent installation (config, skills/plugins, gateway, logging) and
  reports prioritized findings.
- Three reporters: human-readable console (severity-grouped, colored),
  JSON (schema-stable, zod-validated), and SARIF 2.1.0 (for GitHub code
  scanning).
- A documented posture-score formula (100 minus weighted deductions per
  finding severity, floored at 0, banded A–F).
- `--format`, `--fail-on`, `--output`, `--only`/`--skip`, `--no-color`
  flags; `chaperone checks` and `chaperone version` subcommands.
- Hard guardrails: read-only (never modifies the scanned install), no
  network calls during a scan, secrets always masked in every output
  format.
