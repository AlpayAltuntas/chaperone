# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Versioning policy:** a new check landing, or an existing check's
severity changing, is treated as a semver **minor** bump at minimum —
either can change `--fail-on` exit-code behavior for an existing CI
pipeline, even though it isn't a breaking API change in the usual sense.

## [Unreleased]

False-positive fixes from `PROPOSED_FIXES.md` (the 0.2.2 batch). Every
change here can only remove a finding or lower its severity, never add
one, so no existing `--fail-on` pipeline can go from passing to failing.

### Fixed

- `CHAP-NET-001` no longer reports a critical finding for loopback
  addresses written with a port or brackets (`127.0.0.1:8080`,
  `localhost:18789`, `[::1]`, `[::1]:8080`), IPv4-mapped loopback
  (`::ffff:127.0.0.1`), or `localhost.`. Classification now uses
  `node:net` (`isIP`/`BlockList`) after normalizing those forms.
- `CHAP-SUP-002` no longer fires on skills whose `package.json` declares
  no `dependencies`, since there is nothing to install. The sample
  vulnerable fixture goes from 44 to 39 findings as a result.
- `CHAP-AGY-003` no longer treats bare `.send()`/`.delete()`/`.remove()`
  member calls (Express `res.send`, `Map#delete`, `Set#delete`,
  `socket.send`, `classList.remove`) as destructive actions. More specific
  names (`client.sendEmail`, `deleteFile`), non-generic verbs
  (`wallet.transfer`), and bare calls are still detected.
- `CHAP-AGY-002` recognizes ESM skills scoped to their own directory via
  `import.meta.dirname`, `import.meta.url` + `fileURLToPath`, or a
  variable derived from either, instead of flagging them as unscoped.
- `CHAP-AGY-001` downgrades from critical to high when the skill's
  manifest declares `confirmationRequired: true`, and no longer says no
  gate was found. It's still reported because a self-declared gate
  can't be verified statically.
- `--baseline` matching is now portable: findings are compared on check
  ID, file path relative to the scan target, and detail. A baseline
  captured at one path matches the same install at another path (before
  this, moving an install made every finding "new"), and message
  rewording in a later release no longer resurfaces findings. Existing
  0.2.x baseline files keep working unchanged.
- `--profile mcp` no longer runs the seven checks that read keys only
  the default config format has (`CHAP-OBS-001/002/003`,
  `CHAP-INJ-001/003/004/005`), which previously reported a missing audit
  log and kill switch on every MCP scan. Those checks are listed in the
  report's "Skipped" section, and `CHECKS.md`/`chaperone explain` show
  their profile scope.

## [0.2.1] - 2026-09-20

Packaging-metadata-only release — no CLI behavior change.

### Fixed

- `package.json` now declares `main`/`types`/`exports` (pointing at
  `dist/cli.js`/`dist/cli.d.ts`, safe to import without side effects —
  the module only runs the CLI when invoked as the actual entry script,
  never on plain `import`), fixing bundle-size analyzers (e.g. Socket's
  bundlephobia-style check) that couldn't resolve an entry point for a
  `bin`-only package before this.
- Added a missing `author` field, matching the npm registry's existing
  maintainer record.

## [0.2.0] - 2026-09-20

The full `improvement_plan.md` build-out (Phases 1-24) — every check,
command, and flag below shipped since `0.1.0`.

### Added

- 7 new checks, bringing the catalog from 22 to 29:
  - `CHAP-SEC-005` (High) — a secret already present in existing log
    content, not just secrets likely to reach logs in future.
  - `CHAP-SEC-006` (High) — a sidecar secret file (`.env`, `.env.local`,
    `secrets.yaml`/`secrets.json`) exposed alongside the main config.
  - `CHAP-SEC-007` (Low) — config references an environment variable
    that isn't set (advisory/best-effort; documented caveat).
  - `CHAP-SUP-005` (Critical) — obfuscated or dynamically-evaluated code
    (`eval`/`new Function`/`atob`-then-eval chains), found via real AST
    parsing rather than regex.
  - `CHAP-SUP-006` (Medium) — typosquat-risk dependency name.
  - `CHAP-INJ-005` (Medium) — inbound channels that don't distinguish
    trust level from one another.
  - `CHAP-OBS-004` (Medium) — a persistent memory/state store exposed
    the same way sidecar secret files are.
- New commands: `chaperone explain <check-id>` (prints a check's full
  rationale and remediation from the same source `CHECKS.md` is
  generated from), `chaperone fix` (guided, confirmation-gated
  remediation for a narrow set of safe, reversible fixes — the one
  documented exception to "never modifies the scanned install"), and
  `chaperone check-update` (an explicit, opt-in check against the npm
  registry for a newer Chaperone version — the one documented exception
  to "no network calls," never run implicitly by `scan`).
- Three new reporter formats, alongside console/JSON/SARIF: `--format
markdown`, `--format gha` (GitHub Actions `::warning file=...::`
  annotations), and `--format html` (a single self-contained report
  file).
- New CLI flags: `--only-category`/`--skip-category`, `--min-severity`
  (display filter, distinct from `--fail-on`), `--quiet` and
  `--summary-only` console modes, environment-variable equivalents for
  common flags (`CHAPERONE_FAIL_ON`, `CHAPERONE_FORMAT`, etc.),
  `--config <file>` (`.chaperonerc.json` support for
  `severityOverrides`, `ignore` with `expires`, `disabledChecks`, and a
  `SEVERITY_SCORE_WEIGHT` override), `--baseline <file>` (report only
  findings new since a prior saved JSON report), `--profile` (agent
  framework detection), `--all`/multi-root scanning, `--docker`
  (Docker-aware discovery: `Dockerfile`/`docker-compose.yml` config and
  secrets surfaces), and `--plugin` (a documented plugin API for
  third-party checks).
- AST-based capability detection (TypeScript compiler API) replacing
  regex-based shell/fs/network/destructive-keyword detection in skill
  scanning, improving accuracy for `CHAP-AGY-001..004` and `CHAP-INJ-002`
  and removing the word-boundary fixture workaround the regex approach
  needed.
- First-cut non-JS skill support (Python capability detection) and a
  real agent-framework adapter/profile (MCP-based agents).
- An offline vulnerability database backing `CHAP-SUP-003`, replacing
  the v1 "any `package.json`" heuristic with real known-CVE matching.
- Real `.gitignore` semantics (via the `ignore` package: `**`, nested
  `.gitignore` support) for `CHAP-SEC-002`.
- Line numbers in findings for YAML-config-sourced results
  (`Finding.location.line`), via `YAML.parseDocument` source ranges.
- Expanded testing infrastructure: snapshot tests, fuzz tests,
  performance tests, and non-blocking mutation testing (Stryker) scoped
  to the highest-value parsing modules.
- `CHANGELOG.md`, `SECURITY.md`, issue/PR templates, a `CHAPERONE` vs.
  gitleaks/trufflehog/npm-audit/Snyk comparison in the README, a
  `npm pack` → install → smoke-test CI job, Dependabot + `npm audit`
  CI checks, a coverage badge, and a tag-triggered GitHub Actions OIDC
  "trusted publishing" release workflow (`npm publish --provenance`)
  replacing the manual 2FA/token flow used for `0.1.0`.

### Changed

- `CHAP-SUP-003` severity: demoted from `High` to `Info` early in this
  cycle pending the real vulnerability-database fix above, then restored
  to `High` once that fix landed — the `Info` demotion never shipped in
  a release.

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
