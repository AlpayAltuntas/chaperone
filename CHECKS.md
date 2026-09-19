# Chaperone check catalog

This catalog lists every check Chaperone implements — the original set
from `instruction.md` §7 (v1 Phase 3), plus checks added since via
`improvement_plan.md`'s implementation plan. **Generated from the
`ALL_CHECKS` registry** (`src/checks/index.ts`) by `npm run
docs:checks` — do not hand-edit; CI (`npm run docs:checks:check`) fails
the build if this file is stale relative to the registry.

Run `chaperone scan <path>` to run every check below against an install.
`chaperone explain <check-id>` prints one check's full detail from the
same source this file is generated from.

## Posture score

Start at 100 and subtract a fixed weight for every finding, by severity,
then floor at 0:

| Severity | Weight |
| -------- | -----: |
| Critical |     25 |
| High     |     15 |
| Medium   |      7 |
| Low      |      3 |
| Info     |      0 |

`info`-severity findings (currently only ever an internal check-error
record — see `engine/index.ts`) never affect the score. The score maps to
a letter band:

| Score  | Band |
| ------ | :--: |
| 90–100 |  A   |
| 75–89  |  B   |
| 60–74  |  C   |
| 40–59  |  D   |
| 0–39   |  F   |

Available in the JSON reporter's `summary.score`/`summary.band` (`--format
json`), and in the console reporter's summary line (`— posture score
X/100 (band)`, added in Phase 7 alongside `--quiet`/`--summary-only`).

**A note on CHAP-SUP-003:** its deliberately weak v1 heuristic (see below)
fires on essentially any skill with a `package.json`. It's `Info`
severity, not `High` — demoted so a signal this weak can't drag down a
genuinely hardened install's score or trip `--fail-on high` on its own
(see `test/scan/fullCatalog.test.ts`, and `improvement_plan.md` 1.15).

---

## Category A — Secrets & credential hygiene

### CHAP-SEC-001 — Plaintext secrets in config

- **Severity:** High
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** API keys, tokens, passwords, and similar credentials stored directly in the config file as literal values.
- **Heuristic:** A config key whose name looks secret-bearing (`api_key`, `token`, `secret`, `password`, `credential`, case-insensitive) holds a literal string value rather than an indirect reference (`${VAR}`, `$VAR`, `env:VAR`). The literal value is masked (e.g. `sk-…wxyz`) before it ever reaches this check or any report — the real value is never printed. For a YAML config, the finding includes a real source line number (via `YAML.parseDocument`); a JSON config has no equivalent free CST-with-positions, so its findings report a `null` line.
- **Remediation:** Move the value to an environment variable or a secrets manager and reference it indirectly in config.

### CHAP-SEC-002 — Secrets in a git-tracked path

- **Severity:** High
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** A config file holding a literal secret that sits inside a git repository without being covered by that repo's `.gitignore`.
- **Heuristic:** An ancestor `.git` directory exists above the config file (discovery-detected), the config holds at least one literal secret (see CHAP-SEC-001), and the config's path relative to the repo root doesn't match any pattern in the repo-root or a nested `.gitignore` between the git root and the scanned target. Matching uses the `ignore` npm package (real gitignore semantics, including `**` and nested `.gitignore` files); see `checks/shared/gitignoreMatch.ts`. Known gap, not solved: `.git/info/exclude` and a user's global `core.excludesFile` aren't read, and "not gitignored" isn't the same as "actually tracked" (see DECISIONS.md).
- **Remediation:** Add the config/secret file to .gitignore, and rotate any key that may already have been committed.

### CHAP-SEC-003 — Overly permissive file permissions

- **Severity:** Medium
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** The config file being readable by group or other.
- **Heuristic:** POSIX file mode broader than `0600` (i.e. any group/other read bit set). Meaningful on macOS/Linux; not a reliable signal on platforms without POSIX permission bits.
- **Remediation:** `chmod 600` the config file (and `chmod 700` its directory).

### CHAP-SEC-004 — Secrets likely to reach logs

- **Severity:** Medium
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** Verbose logging that's likely to capture secrets, or a log file itself exposed to other local users.
- **Heuristic:** Fires when either: the log level is `debug`/`trace`/`verbose` while the config holds a literal secret, or the log file is readable by group/other. Either reason alone is enough; both are reported together when both hold.
- **Remediation:** Raise the log level away from debug/trace, redact secrets before logging, and restrict the log file to owner-only access.

### CHAP-SEC-005 — Secret already present in existing log content

- **Severity:** High
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** A secret-shaped value already written into the log file's existing content — distinct from CHAP-SEC-004/CHAP-OBS-002, which only reason about whether logging config is likely to leak going forward, not whether it already has.
- **Heuristic:** (Deliberately simple, v1.) Scans up to the last 256 KiB of the log file (bounded — see `discovery/logContentScanner.ts`) for `key=value`/`"key": "value"`-shaped substrings where the key looks secret-bearing (the same `looksLikeSecretKeyName` heuristic CHAP-SEC-001 uses) and the value is at least 8 characters. A generic high-entropy-string scanner was the documented alternative (`improvement_plan.md` 2.1); this reuses existing, tested logic instead. Matched values are masked before ever reaching the model — the real value is never retained or printed, same guarantee as config secrets.
- **Remediation:** Rotate the leaked credential, purge or redact the log file, and fix the logging behavior that caused it to be written.

### CHAP-SEC-006 — Sidecar secret file exposed

- **Severity:** High
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** A sidecar secret file (`.env`, `.env.local`, `secrets.yaml`, `secrets.yml`, `secrets.json`) discovered alongside the main config, holding a literal secret that's either git-tracked and not gitignored, or readable by group/other.
- **Heuristic:** Applies the exact same two checks CHAP-SEC-002/CHAP-SEC-003 apply to the main config file, to each discovered sidecar file instead: the file holds at least one literal (non-env-reference) secret field (masked the same way `config.yaml` is — see `discovery/configParser.ts`/`discovery/sidecarSecrets.ts`), and either its path relative to an ancestor git root isn't covered by the repo's `.gitignore`, or its POSIX mode is broader than `0600`. Both reasons are reported together in one finding when both hold.
- **Remediation:** Add the file to .gitignore, rotate any key that may already have been committed, and restrict it to owner-only access (chmod 600).

### CHAP-SEC-007 — Config references an environment variable that isn't set

- **Severity:** Low
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** A config field using a bare `${VAR}`/`$VAR`/`env:VAR` reference where `VAR` isn't set (or is empty) in Chaperone's own process environment at scan time.
- **Heuristic:** (Explicitly advisory/low-confidence.) Chaperone runs as a separate process from the agent and may not share its real environment — e.g. the agent could be launched via `systemd`/`launchd` with its own `EnvironmentFile` Chaperone never sees. The finding message states this caveat directly, not just here. Only bare references are checked; a reference with a `:-`/`:=`/`:?`/`:+` fallback/default resolves to something even when the variable itself is unset, so it's silently skipped rather than risk a false positive. Reports a real source line number for a YAML config, `null` for JSON (see CHAP-SEC-001).
- **Remediation:** Confirm the variable is actually set in the environment the agent runs under; an unresolved reference can mean the agent starts with an empty or broken credential.

## Category B — Excessive agency & permissions

### CHAP-AGY-001 — Unrestricted shell execution

- **Severity:** Critical
- **OWASP:** LLM08 — Excessive Agency
- **Detects:** Skills/plugins that can run arbitrary shell commands.
- **Heuristic:** A skill's source contains a shell/exec/spawn capability (`child_process`, `exec`/`execSync`, `spawn`/`spawnSync`). v1 does not yet detect a command allowlist or confirmation gate (see DECISIONS.md), so any detected shell capability is treated as unrestricted.
- **Remediation:** Constrain the skill to an explicit command allowlist, require confirmation for shell actions, or sandbox its execution.

### CHAP-AGY-002 — Unrestricted filesystem access

- **Severity:** High
- **OWASP:** LLM08 — Excessive Agency
- **Detects:** Skills that write/delete files with no scoping to a fixed workspace directory.
- **Heuristic:** The skill writes files (`fs.writeFile`/`unlink`/etc.) and its source shows no evidence of scoping — no `path.join(__dirname, ...)` (or `.resolve`) pattern and no constant named like `WORKSPACE`/`SANDBOX`/`SCOPED`. A static proxy for "no path scoping", not true taint tracking.
- **Remediation:** Scope the skill's file access to a dedicated workspace directory and deny path traversal outside it.

### CHAP-AGY-003 — Destructive action without confirmation

- **Severity:** High
- **OWASP:** LLM08 — Excessive Agency
- **Detects:** Skills that can delete data, send messages, spend money, or otherwise act irreversibly with no human-in-the-loop gate.
- **Heuristic:** The skill's source contains a destructive-action keyword as a standalone word (`delete`, `send`, `transfer`, `purchase`, `deploy`, `remove`, `pay`), and its manifest does not declare `confirmationRequired: true` (checked at the manifest's top level or nested under `capabilities`) — an invented-but-documented convention, no real manifest schema exists for these example agents (see DECISIONS.md).
- **Remediation:** Require explicit confirmation before this action runs (or add a dry-run mode).

### CHAP-AGY-004 — Broad network egress from a skill

- **Severity:** Medium
- **OWASP:** LLM08 — Excessive Agency / LLM06
- **Detects:** Skills permitted to call arbitrary external endpoints.
- **Heuristic:** The skill's source shows network capability (`fetch`, `http(s).request`, `axios`/`node-fetch`) and its manifest declares no non-empty `domainAllowlist` array (same manifest-convention caveat as CHAP-AGY-003).
- **Remediation:** Allowlist the specific destination domain(s) the skill needs and log outbound calls.

## Category C — Supply chain & skill provenance

### CHAP-SUP-001 — Skill from an unverified source

- **Severity:** High
- **OWASP:** LLM05 — Supply Chain
- **Detects:** Skills installed from an unpinned ref or with no verifiable provenance.
- **Heuristic:** The skill's manifest doesn't confirm a pinned version/ref (`pinnedRef !== true` — covers both an explicitly unpinned version like `"latest"` and a manifest with no version/ref info at all).
- **Remediation:** Pin the skill to an explicit version or commit, prefer reviewed sources, and verify the author.

### CHAP-SUP-002 — No integrity verification for skill dependencies

- **Severity:** Medium
- **OWASP:** LLM05 — Supply Chain
- **Detects:** Skill dependencies installed with no lockfile.
- **Heuristic:** The skill has a `package.json` but no `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` alongside it.
- **Remediation:** Commit a lockfile alongside the manifest and enable integrity checks.

### CHAP-SUP-003 — Known-vulnerable dependency

- **Severity:** High
- **OWASP:** LLM05 — Supply Chain
- **Detects:** A skill dependency whose declared version matches a known vulnerability in a small, bundled, offline snapshot (OSV.dev-sourced).
- **Heuristic:** Compares each skill's package.json dependency version specifiers against `shared/vulnDb.ts`, a curated, offline snapshot of real advisories for a small set of well-known npm packages, refreshed out-of-band via `npm run refresh:vulndb` (never during a scan — see `scripts/refreshVulnDb.ts`). A specifier's first X.Y.Z-shaped token stands in for the version, since no lockfile/node_modules resolution is available in a static config-only scan; a specifier with no such token (`"latest"`, `"*"`, a git URL) is skipped rather than guessed at. Not exhaustive — only tracks the packages in the bundled snapshot, not the full OSV/npm-advisory database.
- **Remediation:** Upgrade the dependency to a patched version (or remove it if unused). Run `npm audit` for a live, comprehensive check beyond this offline snapshot.

### CHAP-SUP-004 — Dangerous install pattern

- **Severity:** Medium
- **OWASP:** LLM05 — Supply Chain
- **Detects:** Skill install scripts/docs that pipe a remote script into a shell, use `sudo`, or bootstrap a system package manager.
- **Heuristic:** `curl`/`wget` piped into `sh`/`bash`, `sudo`, `apt-get install`, or `brew install`, found in `package.json`'s `preinstall`/`install`/`postinstall` scripts, any `*.sh` file, or any `README*` in the skill directory.
- **Remediation:** Review the install script by hand; prefer a vetted, minimal setup with no piped-shell or sudo steps.

### CHAP-SUP-005 — Obfuscated or dynamically-evaluated code

- **Severity:** Critical
- **OWASP:** LLM05 — Supply Chain
- **Detects:** A skill using eval(), the Function constructor, or a decode-then-execute chain (e.g. eval(atob(payload))) to run dynamically-constructed code.
- **Heuristic:** Any call to the `eval`/`Function` globals (bare, or `new Function(...)`) in a skill's source. Flagged unconditionally regardless of what's being evaluated — a real backdoor and a benign use are equally invisible to static review once code is constructed/evaluated at runtime, so there's no confident way to distinguish them from source alone.
- **Remediation:** Avoid dynamic code evaluation entirely. If genuinely needed, review the exact string being evaluated by hand and vendor/pin it rather than constructing or fetching it at runtime.

### CHAP-SUP-006 — Typosquat-risk dependency name

- **Severity:** Medium
- **OWASP:** LLM05 — Supply Chain
- **Detects:** A skill dependency whose name is suspiciously close (small edit distance) to a well-known popular package name (e.g. 'reqeust' vs 'request') — a common typosquatting technique.
- **Heuristic:** The dependency name isn't itself a well-known package, is at least 4 characters, and has a Levenshtein (edit) distance of 1-2 from a well-known package name in a small bundled reference list (no live registry lookup — Chaperone makes no outbound network calls). Not exhaustive: a name not close to anything on that list is never flagged.
- **Remediation:** Double check the exact spelling against the real package on the registry before installing, and remove the dependency if it was added by mistake.

## Category D — Prompt-injection surface

### CHAP-INJ-001 — Untrusted input flows straight to the model

- **Severity:** High
- **OWASP:** LLM01 — Prompt Injection
- **Detects:** An active inbound message channel with no trust boundary separating untrusted content before it reaches the model.
- **Heuristic:** At least one `channels.*.enabled` is `true` in config, and `trust.mark_untrusted_input` is not `true`.
- **Remediation:** Mark untrusted inbound content explicitly, keep it separated from system instructions in the prompt, and filter it before forwarding to the model.

### CHAP-INJ-002 — Tool output treated as trusted

- **Severity:** Medium
- **OWASP:** LLM02 — Insecure Output Handling
- **Detects:** A skill whose output could drive another tool with no validation step — either a confirmed data-flow chain (a network/filesystem result traced into a shell-exec call's argument) or, more weakly, just both capabilities being present in the same file.
- **Heuristic:** A skill that can execute shell commands and also has network or filesystem-read capability. When a bounded intra-file taint trace confirms the network/fs result actually reaches the shell-exec call's argument, this is reported at `high` severity as a confirmed chain; otherwise it's the weaker `medium`-severity shape-match (both capabilities merely present, not traced) — Chaperone still has no cross-function/file data-flow analysis.
- **Remediation:** Validate/escape a tool's output before it can drive another tool; never auto-execute model or tool output.

### CHAP-INJ-003 — Actions triggerable by inbound messages without an allowlist

- **Severity:** High
- **OWASP:** LLM01 — Prompt Injection / LLM08 — Excessive Agency
- **Detects:** Any inbound message being able to invoke any tool.
- **Heuristic:** At least one channel is active and `trust.tool_allowlist` is empty or absent (same manifest-convention caveat as CHAP-AGY-003/004).
- **Remediation:** Restrict which tools each channel/sender can invoke with an explicit allowlist.

### CHAP-INJ-004 — Auto-execution of links/commands from messages

- **Severity:** High
- **OWASP:** LLM01 — Prompt Injection
- **Detects:** Config that auto-opens links or auto-runs commands found in inbound messages.
- **Heuristic:** `trust.auto_execute_links` is `true`.
- **Remediation:** Disable auto-execution of links/commands found in messages; require explicit confirmation instead.

### CHAP-INJ-005 — Inbound channels do not distinguish trust level

- **Severity:** Medium
- **OWASP:** LLM01 — Prompt Injection
- **Detects:** A non-empty global tool allowlist applied uniformly to a mix of public and private inbound channels, with no channel-specific restriction narrowing what a public (untrusted) channel can invoke.
- **Heuristic:** At least two channels are enabled, the global `trust.tool_allowlist` is non-empty, at least one enabled channel is public (`channels.<name>.public` — missing defaults to `true`/untrusted, same conservative-default posture as CHAP-INJ-001) with no channel-specific `channels.<name>.tool_allowlist` override, and at least one enabled channel is private (`public: false`). Same manifest-convention caveat as CHAP-AGY-003/004 — no real schema exists for these example agents.
- **Remediation:** Declare a channel-specific tool_allowlist for each public/untrusted channel, narrower than what private/admin-only channels are permitted to invoke.

## Category E — Exposure & network posture

### CHAP-NET-001 — Gateway bound beyond localhost

- **Severity:** Critical
- **OWASP:** LLM06 / general
- **Detects:** The gateway daemon listening on an interface other than localhost (e.g. `0.0.0.0`), making it reachable from other hosts.
- **Heuristic:** `gateway.host` in config is present and is not `127.0.0.1`, `localhost`, or `::1`.
- **Remediation:** Bind the gateway to `127.0.0.1`/`localhost`; put anything that must be reachable remotely behind a tunnel with authentication.

### CHAP-NET-002 — Missing or weak auth on the gateway control API

- **Severity:** High
- **OWASP:** General
- **Detects:** The gateway control API with no auth configured, or a default/empty credential.
- **Heuristic:** `gateway.auth` is absent, or its `token` is empty or a common default value (`changeme`, `admin`, `password`, `default`, `token`, case-insensitive).
- **Remediation:** Require a strong, randomly-generated token for the gateway control API and rotate any default value.

### CHAP-NET-003 — Plaintext transport on the gateway

- **Severity:** Medium
- **OWASP:** General
- **Detects:** The gateway explicitly configured without TLS.
- **Heuristic:** `gateway.tls` is explicitly `false`. Silent when TLS isn't mentioned in config at all — v1 doesn't have a confident signal either way in that case.
- **Remediation:** Enable TLS on the gateway and disable any plaintext fallback.

## Category F — Observability & recoverability

### CHAP-OBS-001 — No audit log of agent actions

- **Severity:** Medium
- **OWASP:** LLM08-adjacent
- **Detects:** Tool invocations/actions that aren't logged.
- **Heuristic:** `logging.audit.enabled` is not `true` (covers both an explicitly disabled audit log and no logging config at all).
- **Remediation:** Enable an append-only audit log of every tool invocation/action the agent takes.

### CHAP-OBS-002 — Sensitive data in plaintext logs

- **Severity:** Medium
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** Log config that doesn't confirm secrets/message bodies are redacted.
- **Heuristic:** Logging is configured and `logging.redact_secrets` is not `true`.
- **Remediation:** Redact secrets and sensitive message content before logging, and restrict access to the log file.

### CHAP-OBS-003 — No documented kill switch / revocation path

- **Severity:** Low
- **OWASP:** General
- **Detects:** No documented quick way to stop the agent and revoke its access.
- **Heuristic:** None of `KILL_SWITCH.md`, `STOP.md`, `kill-switch.sh`, or `revoke.sh` exists at the install root — a documented, invented naming convention (no real spec exists for this); an install documenting a kill switch any other way won't be detected in v1.
- **Remediation:** Document a kill switch (how to stop the agent) and a script or checklist to revoke/rotate its credentials.

### CHAP-OBS-004 — Persistent memory/state store exposed

- **Severity:** Medium
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** A configured persistent memory/state directory (one of `instruction.md` §2's five discoverable artifacts) that's readable by group/other, or git-tracked and not gitignored.
- **Heuristic:** Mirrors CHAP-SEC-002/CHAP-SEC-003, applied to a `memory_dir`/`state_dir` config field (mirroring `skills_dir`'s existing pattern — see `discovery/memory.ts`) instead of the config file. No content inside the directory is ever read; only its existence, permission mode, and git-tracking status. Silent when the directory is configured but doesn't exist on disk.
- **Remediation:** Restrict the memory/state directory to owner-only access (chmod 700) and add it to .gitignore — it can accumulate sensitive conversational content over time.
