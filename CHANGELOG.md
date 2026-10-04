# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Versioning policy:** a new check landing, or an existing check's
severity changing, is treated as a semver **minor** bump at minimum —
either can change `--fail-on` exit-code behavior for an existing CI
pipeline, even though it isn't a breaking API change in the usual sense.

## [Unreleased]

Supply chain and remediation from `PROPOSED_FIXES.md` (the 0.5.0 batch).

### May change CI results

- `CHAP-SUP-003` reads lockfiles (`package-lock.json` v1–v3,
  `npm-shrinkwrap.json`, `yarn.lock` v1, `pnpm-lock.yaml`) and matches
  every resolved version, direct and transitive, instead of the
  `package.json` specifier's floor. A transitive vulnerable package is
  now reported, and a range whose floor is vulnerable but whose locked
  version is patched no longer is. Without a lockfile, the old floor
  match is used and the message says so.
- The bundled vulnerability snapshot covers about 80 packages agent
  skills commonly use (was 2), refreshed from OSV.dev on 2026-10-04.
- New check `CHAP-SUP-007` (critical), "Known-malicious package
  version": a dependency, direct or transitive, at a version OSV lists as
  malware (the event-stream, ua-parser-js, chalk/debug, nx,
  @solana/web3.js, and eslint-config-prettier compromises, among others).
- `CHAP-NET-002` also flags a literal gateway token shorter than 16
  characters or equal to another secret in the config, and is medium
  (not high) when the gateway is bound to loopback.
- **Posture score version 2:** repeats of the same check diminish (full
  weight, then half, then a quarter, ...) and are capped at twice the
  check's weight, so one problem repeated across many skills no longer
  sinks the score on its own. Scores for the same findings will differ
  from 0.4.x. The JSON report's `summary.scoreVersion` is `2`.

### Added

- `--vuln-db <file>` (`CHAPERONE_VULN_DB`): match against an OSV JSON
  export as well as the bundled snapshot, read locally, never fetched.
- Reports show the vulnerability data's snapshot date (console/markdown
  header, `advisoryData` in JSON) so staleness is visible.
- `chaperone fix` has seven new fixers (`CHAP-SEC-002`, `CHAP-SEC-003`,
  `CHAP-SEC-006`, `CHAP-SEC-008`, `CHAP-OBS-004`, `CHAP-NET-001`,
  `CHAP-INJ-004`), `--all` to preview every fix from one scan, and
  `--write-env` for `CHAP-SEC-001` to move the literal values into a
  `0600` `.env` (gitignored) instead of leaving you to store them.

### Changed

- `chaperone fix` edits JSON configs in place instead of re-serializing
  them, so formatting and key order are kept. Each plan ends with notes:
  the variable names to export, and a reminder to rotate credentials in
  a git repository.
- `npm run refresh:vulndb` also writes `src/checks/shared/maliciousDb.ts`,
  and its OSV parsing moved to `src/checks/shared/osv.ts` for reuse by
  `--vuln-db`.

## [0.4.0] - Unreleased

Real-world coverage from `PROPOSED_FIXES.md` (the 0.4.0 batch).

### May change CI results

- `--profile mcp` now analyzes how each server is launched instead of
  treating every server as capability-free (`PROPOSED_FIXES.md` 3.9). A
  shell run with `-c` reports `CHAP-AGY-001` (and `CHAP-SUP-004` for a
  piped download in its command), the filesystem server rooted at `/`,
  `~`, or a drive root reports `CHAP-AGY-002`, and a remote server on
  plaintext `http://` reports `CHAP-NET-003`. A config with no servers is
  now nothing scanned (exit 1).
- New check `CHAP-AGY-005` (critical), "Container launched with
  host-level privileges": an MCP server started with `docker run`/
  `podman run`, or a `docker-compose.yml`/`compose.yaml` service in the
  install directory, using `--privileged`, `--cap-add=ALL`/`SYS_ADMIN`,
  a host PID/network/IPC/user namespace, or a bind mount of `/`, the
  Docker socket, or `$HOME`.

- New `--profile claude-code` with six checks for Claude Code settings
  (`PROPOSED_FIXES.md` 6.1): `CHAP-AGY-006` (bypassPermissions mode),
  `CHAP-AGY-007` (shell commands pre-approved too broadly),
  `CHAP-AGY-008` (web fetches pre-approved for every domain),
  `CHAP-SEC-009` (no deny rule for `.env`/`~/.ssh`), `CHAP-SUP-008`
  (`enableAllProjectMcpServers`), and `CHAP-SUP-009` (a hook or helper
  command that runs downloaded code). `CHAP-SEC-001` also covers
  literal secrets in a settings file's `env` block.
- **The profile is auto-detected when `--profile` isn't given**
  (`PROPOSED_FIXES.md` 6.3). A directory holding only an MCP config or
  Claude Code settings is now scanned with that profile instead of
  failing as "nothing scanned" under the default profile, and a
  directory matching both the default format and another profile stops
  with an error asking for `--profile`.
- Python skills (`PROPOSED_FIXES.md` 3.4): calls are resolved through
  `import x as y` / `from x import y` aliases; comments and strings no
  longer count; `cursor.exec(...)` is no longer mistaken for `exec`;
  `asyncio`/`pty` subprocesses, `httpx`/`aiohttp`/`urllib3`, pathlib
  writes, and unsafe deserialization (`pickle`/`marshal`/`dill` loads,
  `yaml.load` without a safe loader) are detected. `requirements.txt`
  and `pyproject.toml` dependencies are read, so `CHAP-SUP-002` reports
  a Python skill with no `poetry.lock`/`uv.lock`/`Pipfile.lock`/
  `pdm.lock` (a fully hashed `requirements.txt` counts as its own lock).

### Added

- Reports show the discovery profile when it was detected or isn't
  `default` (console/markdown header, and a `profile` field in JSON).
- MCP discovery reads VS Code's `servers` key, probes `.vscode/mcp.json`
  and `.cursor/mcp.json`, reads the per-project servers in Claude Code's
  `~/.claude.json`, accepts a path to any MCP config file, and, with no
  path and nothing in the current directory, falls back to the
  user-level Claude Desktop, Cursor, and Claude Code configs.
- MCP skills carry a `launch` block (command with masked args and env
  key names, or masked URL and header key names; never values), and the
  model has a `containers` list.

## [0.3.0] - Unreleased

Detection-accuracy fixes from `PROPOSED_FIXES.md` (the 0.3.0 batch).

### May change CI results

- `chaperone scan <path>` now exits `1` when the path doesn't exist, is a
  file other than the agent's config file, or is a directory with
  neither a config file nor a `skills/` directory. Before, it exited `0`
  with grade A, so a typo in a CI job's path passed forever. Under
  `--profile mcp`, a missing or unparseable MCP config also exits `1`.
  An unscanned target no longer gets phantom `CHAP-OBS-001`/`CHAP-OBS-003`
  findings, and console/markdown/html reports show "no posture score
  (nothing scanned)" instead of 100/100 (A).
- Config keys are now read in camelCase and kebab-case as well as
  snake_case (`autoExecuteLinks`, `markUntrustedInput`, `toolAllowlist`,
  `redactSecrets`, `skillsDir`, `memoryDir`/`stateDir`). A camelCase
  JSON config used to get false positives from `CHAP-INJ-001`/`003`/`005`,
  missed `CHAP-INJ-004` entirely, and ignored a custom `skillsDir` (so its
  skills were never scanned). Those findings and skills now appear.
- `CHAP-SEC-001` (and `CHAP-SEC-006` for sidecar files) now recognizes a
  secret by its value, not only its key name: provider-prefixed tokens
  (`sk-ant-`, `sk-proj-`, `ghp_`, `github_pat_`, `xoxb-`, `AKIA`,
  `AIza`, `glpat-`, `npm_`, `hf_`, `sk_live_`), `Bearer`/`Basic`
  credentials, PEM private keys, and passwords in URLs. Keys ending in
  `auth`, `authorization`, `bearer`, `cookie`, or `session` also count
  when the value looks like a credential. Of five realistic secrets in a
  probe config, one used to be caught; all five are now. `CHAP-SEC-005`
  applies the same value patterns to log lines, so a logged
  `Authorization: Bearer …` header is reported.
- Skill source analysis recognizes many more APIs and indirection forms.
  Shell: `execa`, `shelljs.exec`, `zx` `$`, `cross-spawn`, `node-pty`,
  `child_process.fork`, `Bun.spawn`, `new Deno.Command`. Filesystem
  writes: `fs.promises.*`, `rename`/`copyFile`/`mkdir`/`chmod`/
  `createWriteStream` and more, `fs-extra`, `rimraf`, `del`. Network:
  `undici`, `got`, `ky`, `superagent`, `ws`, `net`/`tls`/`dgram`/`http2`,
  and global `WebSocket`/`XMLHttpRequest`/`EventSource`. Dynamic code
  (`CHAP-SUP-005`): indirect eval (`(0, eval)`, `globalThis.eval`), eval
  aliases, `vm`, non-literal `require()`/`import()`, string
  `setTimeout`, and `module._compile`. One level of aliasing
  (`const run = cp['exec']; run(c)`), nested namespaces, and
  template-literal keys are resolved. Both probe skills in
  `PROPOSED_FIXES.md` A.9 used to produce no findings and are now fully
  detected. A locally declared `fetch`/`WebSocket`/`Bun` is no longer
  mistaken for the global.
- Skill scanning no longer has trivial blind spots. Dot-directories and
  dot-files are scanned (a payload in `.lib/` used to go unseen), except
  `.git`, `node_modules`, and Python virtualenvs. A directory past the
  depth limit (raised from 4 to 6) is listed under Skipped instead of
  being dropped silently. `.jsx`/`.tsx`/`.mts`/`.cts` files and
  extensionless scripts with a `node`/`deno`/`bun`/`python` shebang are
  analyzed. Files over 256 KB get a pattern pre-pass (`eval(`,
  `Function(`, `atob(`, `child_process`) that feeds `CHAP-SUP-005`,
  instead of being skipped. `CHAP-SUP-004` checks `*.sh` files at any
  depth, the `prepare` lifecycle script, `bash <(curl …)`, PowerShell
  `iwr … | iex`, `base64 -d … | sh`, and `| sudo bash`.
- New check `CHAP-SEC-008` (high), "Agent files writable by other
  users": the config file, install directory, skills directory, any
  skill directory, or the memory directory having a group/other write
  bit. A `chmod 777 skills/` lets any local user plant code the agent
  runs with its own privileges, and writable memory is persistent prompt
  injection. Discovery now records permissions for those directories.
- `CHAP-SEC-006` looks at more sidecar secret files in the install
  root: `.env.*` (except `.env.example`/`.sample`/`.template`/`.dist`/
  `.defaults`), `.envrc`, `.npmrc` (`_authToken`), `.pypirc`, `.netrc`,
  `credentials.json`, `service-account*.json`, and private keys
  (`id_rsa`, `id_ecdsa`, `id_ed25519`, and `*.pem`/`*.key` files that
  hold a PEM private key, not a certificate).
- `CHAP-AGY-002` decides scoping per write call (the other half of
  `PROPOSED_FIXES.md` 2.6). A write is scoped when its path argument is
  the skill's own directory, a fixed non-root path, or built from one
  with `path.join`/`path.resolve`. Any one unscoped write makes the skill
  unscoped, even if another file is scoped, and a variable merely named
  `workspace`/`sandbox` no longer counts (`const workspaceRoot = '/'`
  used to clear every write in the skill).
- Python skills: `CHAP-AGY-003` now takes destructive keywords only from
  module-level `def` names (so `def delete_file` counts and `# delete
old files` or `"-delete"` don't), the Python half of 2.4.

- **Node.js 22 or later is now required** (`engines: >=22`). Node 20
  reached end-of-life on 2026-04-30. CI runs on Node 22.

### Changed

- Skill findings (`CHAP-AGY-001..004`, `CHAP-SUP-005`, `CHAP-INJ-002`)
  now point at the code that triggered them (`index.js:12`) instead of
  the skill's `package.json`, list up to three call sites in the message
  ("Seen at index.js:12 (child_process.execSync), …"), and carry the
  rest as `relatedLocations` in JSON/SARIF. Config findings
  (`CHAP-NET-*`, `CHAP-INJ-001/003/004/005`, `CHAP-OBS-001`) include the
  key's line number. JSON configs now get line numbers too, including
  `CHAP-SEC-001`/`CHAP-SEC-007`. **Baselines:** because a skill
  finding's file path changed, re-create a `--baseline` file after
  upgrading, or those findings will show as new once.
- SARIF output is shaped for GitHub code scanning: file URIs are
  relative to the git repository root (`uriBaseId: SRCROOT`) instead of
  absolute `file://` paths, and absolute paths are also removed from
  message text, so a shared SARIF file no longer contains the local
  directory layout. Results carry `partialFingerprints` (the same stable
  fingerprint `--baseline` uses), rules carry `security-severity`
  (critical 9.5, high 8.0, medium 5.5, low 3.0), `tags`, the check's
  full description, help text, and a `helpUri` into `CHECKS.md`. Every
  check that ran is listed as a rule, not only those that fired.
  `invocations[0].executionSuccessful` is false for a scan that found
  nothing to scan. Related call sites appear as `relatedLocations`. The
  output is validated against the SARIF 2.1.0 schema in the test suite.
- `CHAP-SUP-004` findings for an npm lifecycle script point at the
  skill's real `package.json` (with `scripts.<name>` in the detail)
  instead of the pseudo-path `package.json#scripts.<name>`.
- README: a complete GitHub Actions workflow (SARIF upload plus the HTML
  report as an artifact).
- The model's `SkillCapabilities` has an `evidence` array (capability,
  file, line, API name; never source text), `ConfigModel` has
  `keyLines`, and findings may have `relatedLocations`.

- On Windows, file permission facts report group/other access as
  unknown instead of reading Node's synthesized mode bits, so
  `CHAP-SEC-003`, `CHAP-SEC-006`, `CHAP-OBS-004`, and `CHAP-SEC-008` no
  longer report permission findings there that don't reflect real access
  control.
- Permission facts in the model carry a `role` (`config`, `log`,
  `memory-dir`, `sidecar`, `target-root`, `skills-dir`, `skill-dir`).

- `CHAP-SUP-004` no longer flags `apt-get install`/`brew install` in a
  skill's README (they still count in install scripts), and no longer
  mistakes `curl … | shasum` for piping into a shell.

- Passing the config file itself (`chaperone scan ~/clawd/config.yaml`,
  or an MCP config file under `--profile mcp`) scans its directory
  instead of reporting no config found.

### Security

- Secrets recognized only by their value used to stay unmasked in the
  in-memory model passed to `--plugin` checks. They're now masked, which
  restores the documented "no literal secret is retained in the model"
  invariant. A URL credential is masked as `https://user:***@host`.

## [0.2.2] - Unreleased

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
