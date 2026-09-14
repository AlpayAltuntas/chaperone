# Chaperone check catalog

This catalog lists every check Chaperone currently implements. It's kept in
sync with `src/checks/` as checks are added — see `instruction.md` §7 for
the full planned catalog and §12 for the build phases. Only implemented
checks are listed here; the remaining checks from §7 land in Phase 3.

Run `chaperone scan <path>` to run every check below against an install.

---

## CHAP-SEC-001 — Plaintext secrets in config

- **Severity:** High
- **Category:** Secrets & credential hygiene
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

## CHAP-AGY-001 — Unrestricted shell execution

- **Severity:** Critical
- **Category:** Excessive agency & permissions
- **OWASP:** LLM08 — Excessive Agency
- **Detects:** Skills/plugins that can run arbitrary shell commands.
- **Heuristic:** A skill's source contains a shell/exec/spawn capability
  (`child_process`, `exec`/`execSync`, `spawn`/`spawnSync`). v1 does not yet
  detect a command allowlist or confirmation gate (see `DECISIONS.md`), so
  any detected shell capability is treated as unrestricted.
- **Remediation:** Constrain the skill to an explicit command allowlist,
  require confirmation for shell actions, or sandbox its execution.

## CHAP-NET-001 — Gateway bound beyond localhost

- **Severity:** Critical
- **Category:** Exposure & network posture
- **OWASP:** LLM06 / general
- **Detects:** The gateway daemon listening on an interface other than
  localhost (e.g. `0.0.0.0`), making it reachable from other hosts.
- **Heuristic:** `gateway.host` in config is present and is not
  `127.0.0.1`, `localhost`, or `::1`.
- **Remediation:** Bind the gateway to `127.0.0.1`/`localhost`; put
  anything that must be reachable remotely behind a tunnel with
  authentication.
