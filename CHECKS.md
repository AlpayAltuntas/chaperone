# Chaperone check catalog

This catalog lists every check Chaperone implements — the complete set from
`instruction.md` §7, all landing in Phase 3. Kept in sync with `src/checks/`.

Run `chaperone scan <path>` to run every check below against an install.

**Posture score:** not implemented yet — Phase 4, per §12.

---

## Category A — Secrets & credential hygiene

### CHAP-SEC-001 — Plaintext secrets in config

- **Severity:** High
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** API keys, tokens, passwords, and similar credentials stored
  directly in the config file as literal values.
- **Heuristic:** A config key whose name looks secret-bearing (`api_key`,
  `token`, `secret`, `password`, `credential`, case-insensitive) holds a
  literal string value rather than an indirect reference (`${VAR}`, `$VAR`,
  `env:VAR`). The literal value is masked (e.g. `sk-…wxyz`) before it ever
  reaches this check or any report — the real value is never printed.
- **Remediation:** Move the value to an environment variable or a secrets
  manager and reference it indirectly in config.

### CHAP-SEC-002 — Secrets in a git-tracked path

- **Severity:** High
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** A config file holding a literal secret that sits inside a git
  repository without being covered by that repo's `.gitignore`.
- **Heuristic:** An ancestor `.git` directory exists above the config file
  (discovery-detected), the config holds at least one literal secret (see
  CHAP-SEC-001), and the config's path relative to the repo root doesn't
  match any pattern in the repo-root `.gitignore`. Pattern matching supports
  `*`/`?` wildcards, directory-only and root-anchored patterns, and `!`
  negation — a deliberately small subset of real gitignore semantics (no
  `**`, no nested `.gitignore` files); see `checks/shared/gitignoreMatch.ts`.
- **Remediation:** Add the config/secret file to `.gitignore`, and rotate
  any key that may already have been committed.

### CHAP-SEC-003 — Overly permissive file permissions

- **Severity:** Medium
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** The config file being readable by group or other.
- **Heuristic:** POSIX file mode broader than `0600` (i.e. any group/other
  read bit set). Meaningful on macOS/Linux; not a reliable signal on
  platforms without POSIX permission bits.
- **Remediation:** `chmod 600` the config file (and `chmod 700` its
  directory).

### CHAP-SEC-004 — Secrets likely to reach logs

- **Severity:** Medium
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** Verbose logging that's likely to capture secrets, or a log
  file itself exposed to other local users.
- **Heuristic:** Fires when either: the log level is `debug`/`trace`/
  `verbose` while the config holds a literal secret, **or** the log file is
  readable by group/other. Either reason alone is enough; both are reported
  together when both hold.
- **Remediation:** Raise the log level away from debug/trace, redact
  secrets before logging, and restrict the log file to owner-only access.

## Category B — Excessive agency & permissions

### CHAP-AGY-001 — Unrestricted shell execution

- **Severity:** Critical
- **OWASP:** LLM08 — Excessive Agency
- **Detects:** Skills/plugins that can run arbitrary shell commands.
- **Heuristic:** A skill's source contains a shell/exec/spawn capability
  (`child_process`, `exec`/`execSync`, `spawn`/`spawnSync`). v1 does not yet
  detect a command allowlist or confirmation gate (see DECISIONS.md), so
  any detected shell capability is treated as unrestricted.
- **Remediation:** Constrain the skill to an explicit command allowlist,
  require confirmation for shell actions, or sandbox its execution.

### CHAP-AGY-002 — Unrestricted filesystem access

- **Severity:** High
- **OWASP:** LLM08 — Excessive Agency
- **Detects:** Skills that write/delete files with no scoping to a fixed
  workspace directory.
- **Heuristic:** The skill writes files (`fs.writeFile`/`unlink`/etc.) and
  its source shows no evidence of scoping — no `path.join(__dirname, ...)`
  (or `.resolve`) pattern and no constant named like `WORKSPACE`/`SANDBOX`/
  `SCOPED`. A static proxy for "no path scoping", not true taint tracking.
- **Remediation:** Scope the skill's file access to a dedicated workspace
  directory and deny path traversal outside it.

### CHAP-AGY-003 — Destructive/irreversible action without confirmation

- **Severity:** High
- **OWASP:** LLM08 — Excessive Agency
- **Detects:** Skills that can delete data, send messages, spend money, or
  otherwise act irreversibly with no human-in-the-loop gate.
- **Heuristic:** The skill's source contains a destructive-action keyword
  as a standalone word (`delete`, `send`, `transfer`, `purchase`, `deploy`,
  `remove`, `pay`), and its manifest does not declare
  `confirmationRequired: true` (checked at the manifest's top level or
  nested under `capabilities`) — an invented-but-documented convention, no
  real manifest schema exists for these example agents (see DECISIONS.md).
- **Remediation:** Require explicit confirmation before this action runs
  (or add a dry-run mode).

### CHAP-AGY-004 — Broad network egress from a skill

- **Severity:** Medium
- **OWASP:** LLM08 — Excessive Agency / LLM06
- **Detects:** Skills permitted to call arbitrary external endpoints.
- **Heuristic:** The skill's source shows network capability (`fetch`,
  `http(s).request`, `axios`/`node-fetch`) and its manifest declares no
  non-empty `domainAllowlist` array (same manifest-convention caveat as
  CHAP-AGY-003).
- **Remediation:** Allowlist the specific destination domain(s) the skill
  needs and log outbound calls.

## Category C — Supply chain & skill provenance

### CHAP-SUP-001 — Skill from an unverified source

- **Severity:** High
- **OWASP:** LLM05 — Supply Chain
- **Detects:** Skills installed from an unpinned ref or with no verifiable
  provenance.
- **Heuristic:** The skill's manifest doesn't confirm a pinned version/ref
  (`pinnedRef !== true` — covers both an explicitly unpinned version like
  `"latest"` and a manifest with no version/ref info at all).
- **Remediation:** Pin the skill to an explicit version or commit, prefer
  reviewed sources, and verify the author.

### CHAP-SUP-002 — No integrity verification for skill dependencies

- **Severity:** Medium
- **OWASP:** LLM05 — Supply Chain
- **Detects:** Skill dependencies installed with no lockfile.
- **Heuristic:** The skill has a `package.json` but no
  `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` alongside it.
- **Remediation:** Commit a lockfile alongside the manifest and enable
  integrity checks.

### CHAP-SUP-003 — Dependency manifest not checked for known vulnerabilities

- **Severity:** High
- **OWASP:** LLM05 — Supply Chain
- **Detects:** Any skill dependency manifest, surfaced for manual review.
- **Heuristic (deliberately weak, v1):** Chaperone makes no outbound
  network calls (§14), so it cannot check dependencies against a live
  advisory database. This check simply fires on any skill with a
  `package.json` and points the user at `npm audit` — it fires on a
  hardened install exactly as readily as a vulnerable one. This is a
  documented v1 limitation, not a bug; see `test/checks/chapSup003.test.ts`
  and DECISIONS.md.
- **Remediation:** Run `npm audit` (or your package manager's equivalent)
  inside the skill directory; update or remove vulnerable/unused
  dependencies.

### CHAP-SUP-004 — Dangerous install pattern

- **Severity:** Medium
- **OWASP:** LLM05 — Supply Chain
- **Detects:** Skill install scripts/docs that pipe a remote script into a
  shell, use `sudo`, or bootstrap a system package manager.
- **Heuristic:** `curl`/`wget` piped into `sh`/`bash`, `sudo`, `apt-get install`,
  or `brew install`, found in `package.json`'s
  `preinstall`/`install`/`postinstall` scripts, any `*.sh` file, or any
  `README*` in the skill directory.
- **Remediation:** Review the install script by hand; prefer a vetted,
  minimal setup with no piped-shell or sudo steps.

## Category D — Prompt-injection surface

### CHAP-INJ-001 — Untrusted input flows straight to the model

- **Severity:** High
- **OWASP:** LLM01 — Prompt Injection
- **Detects:** An active inbound message channel with no trust boundary
  separating untrusted content before it reaches the model.
- **Heuristic:** At least one `channels.*.enabled` is `true` in config, and
  `trust.mark_untrusted_input` is not `true`.
- **Remediation:** Mark untrusted inbound content explicitly, keep it
  separated from system instructions in the prompt, and filter it before
  forwarding to the model.

### CHAP-INJ-002 — Tool output treated as trusted

- **Severity:** Medium
- **OWASP:** LLM02 — Insecure Output Handling
- **Detects:** A skill whose output could drive another tool with no
  validation step.
- **Heuristic (a static proxy, not real data-flow analysis):** A skill
  that both ingests external/tool data (network or filesystem capability)
  **and** can execute shell commands — the shape of a tool-output-to-
  shell-execution chain, since Chaperone has no way to confirm data
  actually flows between them.
- **Remediation:** Validate/escape a tool's output before it can drive
  another tool; never auto-execute model or tool output.

### CHAP-INJ-003 — Actions triggerable by inbound messages without an allowlist

- **Severity:** High
- **OWASP:** LLM01 — Prompt Injection / LLM08 — Excessive Agency
- **Detects:** Any inbound message being able to invoke any tool.
- **Heuristic:** At least one channel is active and `trust.tool_allowlist`
  is empty or absent (same manifest-convention caveat as CHAP-AGY-003/004).
- **Remediation:** Restrict which tools each channel/sender can invoke
  with an explicit allowlist.

### CHAP-INJ-004 — Auto-execution of links/commands from messages

- **Severity:** High
- **OWASP:** LLM01 — Prompt Injection
- **Detects:** Config that auto-opens links or auto-runs commands found in
  inbound messages.
- **Heuristic:** `trust.auto_execute_links` is `true`.
- **Remediation:** Disable auto-execution of links/commands found in
  messages; require explicit confirmation instead.

## Category E — Exposure & network posture

### CHAP-NET-001 — Gateway bound beyond localhost

- **Severity:** Critical
- **OWASP:** LLM06 / general
- **Detects:** The gateway daemon listening on an interface other than
  localhost (e.g. `0.0.0.0`), making it reachable from other hosts.
- **Heuristic:** `gateway.host` in config is present and is not
  `127.0.0.1`, `localhost`, or `::1`.
- **Remediation:** Bind the gateway to `127.0.0.1`/`localhost`; put
  anything that must be reachable remotely behind a tunnel with
  authentication.

### CHAP-NET-002 — Missing or weak auth on the gateway control API

- **Severity:** High
- **OWASP:** General
- **Detects:** The gateway control API with no auth configured, or a
  default/empty credential.
- **Heuristic:** `gateway.auth` is absent, or its `token` is empty or a
  common default value (`changeme`, `admin`, `password`, `default`,
  `token`, case-insensitive).
- **Remediation:** Require a strong, randomly-generated token for the
  gateway control API and rotate any default value.

### CHAP-NET-003 — Plaintext transport on the gateway

- **Severity:** Medium
- **OWASP:** General
- **Detects:** The gateway explicitly configured without TLS.
- **Heuristic:** `gateway.tls` is explicitly `false`. Silent when TLS
  isn't mentioned in config at all — v1 doesn't have a confident signal
  either way in that case.
- **Remediation:** Enable TLS on the gateway and disable any plaintext
  fallback.

## Category F — Observability & recoverability

### CHAP-OBS-001 — No audit log of agent actions

- **Severity:** Medium
- **OWASP:** LLM08-adjacent
- **Detects:** Tool invocations/actions that aren't logged.
- **Heuristic:** `logging.audit.enabled` is not `true` (covers both an
  explicitly disabled audit log and no logging config at all).
- **Remediation:** Enable an append-only audit log of every tool
  invocation/action the agent takes.

### CHAP-OBS-002 — Sensitive data in plaintext logs

- **Severity:** Medium
- **OWASP:** LLM06 — Sensitive Information Disclosure
- **Detects:** Log config that doesn't confirm secrets/message bodies are
  redacted.
- **Heuristic:** Logging is configured and `logging.redact_secrets` is not
  `true`.
- **Remediation:** Redact secrets and sensitive message content before
  logging, and restrict access to the log file.

### CHAP-OBS-003 — No documented kill switch / revocation path

- **Severity:** Low
- **OWASP:** General
- **Detects:** No documented quick way to stop the agent and revoke its
  access.
- **Heuristic:** None of `KILL_SWITCH.md`, `STOP.md`, `kill-switch.sh`, or
  `revoke.sh` exists at the install root — a documented, invented naming
  convention (no real spec exists for this); an install documenting a kill
  switch any other way won't be detected in v1.
- **Remediation:** Document a kill switch (how to stop the agent) and a
  script or checklist to revoke/rotate its credentials.
