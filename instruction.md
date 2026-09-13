# Chaperone — Build Specification & Instructions

> **What this document is:** a complete, phase-by-phase build spec for an
> autonomous coding agent (e.g. Claude Code) to implement **Chaperone**, a
> security scanner that audits self-hosted personal AI agents (Clawdbot /
> Moltbot / OpenClaw-style assistants) for security weaknesses.
>
> **How to use it:** read the whole document once before writing any code.
> Then build in the phases described in Section 12, keeping the tool runnable
> and tested at the end of every phase. Do not expand scope beyond Section 3
> without flagging it first.

---

## 0. Meta-instructions for the coding agent

Follow these working rules for the whole project:

1. **Build incrementally and keep it runnable.** After each phase in Section 12,
   the tool must build, lint, pass its tests, and run end-to-end on the sample
   fixtures. Never leave the repo in a broken state between phases.
2. **Write tests alongside code, not after.** Every security check ships with at
   least one fixture that makes it fire (true positive) and one that keeps it
   quiet (true negative). See Section 13.
3. **Do not invent scope.** If something seems needed but isn't in Section 3 or
   Section 7, add a note in a `DECISIONS.md` file and keep going with the
   defined scope. Don't silently add features.
4. **Prefer clarity over cleverness.** This is a security tool people must be
   able to trust and read. Small, well-named, well-commented modules.
5. **Minimal dependencies.** Every added dependency is attack surface. Justify
   each one in `DECISIONS.md`. Prefer the standard library where reasonable.
6. **Read-only and local by default.** Chaperone must never modify the target
   agent's files, never make outbound network calls, and never exfiltrate
   anything it reads. See Section 14 — this is non-negotiable.
7. **Conventional commits.** Use messages like `feat: add secrets scanner`,
   `test: add fixtures for gateway exposure check`, `docs: write README`.
8. **Record decisions.** Keep a running `DECISIONS.md` capturing any non-obvious
   choice (library picks, heuristics, trade-offs) so the reasoning is legible.

---

## 1. Mission

Self-hosted personal AI agents have exploded in popularity. They run locally,
connect to a user's messaging apps (Telegram, WhatsApp, iMessage, Slack, Discord,
Teams), hold persistent memory, and — crucially — **execute real actions** via a
"skills" / plugin system: running shell commands, reading and writing files,
calling external APIs.

That combination (an LLM + broad local access + untrusted inbound messages) is a
serious security exposure that almost nobody audits systematically. Secrets sit
in plaintext configs, skills come from unverified sources, gateways get exposed
beyond localhost, and inbound messages can drive tool execution (prompt
injection).

**Chaperone scans a user's own agent installation and produces a prioritized
security report** — what's dangerous, why it matters, and how to fix it. Think
"a linter for the security posture of your personal AI agent."

**Chaperone is a defensive tool.** It audits the setup you point it at, on your
own machine, read-only. It is not an exploitation tool and must never be built
into one (Section 14).

---

## 2. Background the agent should internalize

Target agents (Clawdbot / Moltbot / OpenClaw and similar) typically have:

- A **config file**, commonly YAML or JSON (e.g. `~/clawd/config.yaml`),
  containing the LLM provider, API keys, connected channels, and settings.
- A **skills / plugins directory** — each skill is code (often Node/TS) that
  defines tools the agent can call. Skills may declare permissions, shell out,
  hit the network, or install system packages.
- A **gateway daemon** that runs persistently (launchd/systemd user service) and
  listens on a local port (e.g. `18789`) to bridge messaging apps to the agent.
- **Persistent memory / state** stored on disk.
- **Logs** of conversations and actions.

Chaperone's job is to discover these artifacts and evaluate them against the
checks in Section 7. It should degrade gracefully: if it can't find a piece, it
reports what it could and could not inspect, rather than crashing.

The checks are grounded in the **OWASP Top 10 for LLM Applications** and in
classic application-security principles (least privilege, secrets hygiene, secure
defaults, defense in depth). Each check in Section 7 carries an OWASP mapping.

---

## 3. Scope

### In scope for v1
- A **command-line tool** that scans a local agent installation.
- **Static inspection** of: config files, skill/plugin manifests and source,
  file permissions, gateway/network settings, logging configuration, and
  dependency manifests (e.g. `package.json` / lockfiles) inside skills.
- A **rule/check engine** with the checks defined in Section 7.
- **Reporters**: human-readable console output and machine-readable JSON; SARIF
  as the third reporter (so results can drop into GitHub code scanning).
- **A severity model** and an overall posture score.
- **Test fixtures**: a deliberately-insecure sample agent and a clean one.
- **Documentation**: README, usage, and a `CHECKS.md` catalog.

### Out of scope for v1 (note as future work, don't build)
- Actively running or exploiting the agent, sending it messages, or performing
  live prompt-injection attacks (that's a *separate* project — see Section 16).
- Auto-remediation / auto-fixing the user's config.
- A GUI or web dashboard (HTML report is a stretch goal only).
- Scanning remote/other people's installations over a network.
- Cloud-hosted agent platforms (v1 targets local self-hosted setups).

---

## 4. Technology stack

- **Language:** TypeScript on Node.js (LTS ≥ 20). Rationale: the target agent
  ecosystem is Node/TS, so this maximizes compatibility and credibility, and it
  matches the intended maintainer's stack.
- **CLI framework:** `commander` (or `yargs`) — pick one, justify in DECISIONS.
- **Config parsing:** a YAML parser (e.g. `yaml`) plus native JSON.
- **Schema/validation:** `zod` for validating parsed structures and for defining
  the report schema.
- **Testing:** `vitest` (or `jest`) with fixtures under `test/fixtures`.
- **Lint/format:** ESLint + Prettier, strict TypeScript (`strict: true`).
- **Output styling:** a small color library (e.g. `picocolors`) — keep it light.
- **SARIF:** emit hand-built SARIF 2.1.0 JSON (no heavy dependency needed).

Keep the dependency list short. Everything above except the parser, CLI, and
zod should be considered optional if it can be avoided cleanly.

---

## 5. High-level architecture

```
+------------------+     +------------------+     +-------------------+
|   Discovery      | --> |   Check Engine   | --> |     Reporters     |
| (find & load     |     | (run all checks  |     | (console / json / |
|  agent artifacts)|     |  over the model) |     |  sarif)           |
+------------------+     +------------------+     +-------------------+
        |                        |                         |
        v                        v                         v
   AgentModel               Finding[]                 rendered output
```

- **Discovery layer**: locates and parses the config, skills, permissions,
  gateway settings, logs config, and dependency manifests into a normalized
  in-memory `AgentModel`. It records what it inspected and what it could not.
- **Check engine**: each check is a pure function `(model) => Finding[]`. The
  engine runs all registered checks and aggregates findings. Checks never do I/O
  themselves — all reads happen in discovery. This keeps checks testable and
  side-effect free.
- **Reporters**: take `Finding[]` + scan metadata and render console, JSON, or
  SARIF. Reporters are pure formatters.

This separation (I/O in discovery, logic in checks, formatting in reporters) is
the core design principle. Enforce it.

---

## 6. Project structure

```
chaperone/
  src/
    cli.ts                 # entry point, arg parsing, wiring
    discovery/
      index.ts             # orchestrates discovery -> AgentModel
      configLocator.ts     # find config files across known locations
      configParser.ts      # parse YAML/JSON into normalized shapes
      skillsScanner.ts     # enumerate & parse skills/plugins
      permissions.ts       # read file modes / ownership
      gateway.ts           # parse gateway/network settings
    model/
      types.ts             # AgentModel, Skill, Finding, Severity, etc. (zod)
    engine/
      index.ts             # registry + runner
      severity.ts          # severity ordering + scoring
    checks/
      secrets/             # CHAP-SEC-*
      agency/              # CHAP-AGY-*
      supplyChain/         # CHAP-SUP-*
      injection/           # CHAP-INJ-*
      network/             # CHAP-NET-*
      observability/       # CHAP-OBS-*
      index.ts             # imports & registers every check
    reporters/
      console.ts
      json.ts
      sarif.ts
      index.ts
  test/
    fixtures/
      vulnerable-agent/    # deliberately insecure sample install
      clean-agent/         # hardened sample install (no findings expected)
    checks/                # one test file per check
    discovery/
  CHECKS.md                # generated/maintained catalog of all checks
  DECISIONS.md
  README.md
  package.json
  tsconfig.json
```

---

## 7. The security checks (the heart of the tool)

Each check has: **ID**, **title**, **severity** (Critical / High / Medium / Low
/ Info), **OWASP LLM mapping**, **what it detects**, **detection heuristic**,
and **remediation**. Implement each as its own module with its own tests. Keep
`CHECKS.md` in sync as a human-readable catalog.

Severities are guidance; make them configurable via a config file later, but ship
sensible defaults now.

### Category A — Secrets & credential hygiene

**CHAP-SEC-001 — Plaintext secrets in config (High)**
OWASP: LLM06 (Sensitive Information Disclosure).
Detects API keys, tokens, passwords stored directly in config files.
Heuristic: known key names (`api_key`, `token`, `secret`, `password`,
provider-specific patterns like `sk-...`) with literal string values rather than
environment-variable references. Report the *location*, never print the secret
value — mask it (`sk-…last4`).
Remediation: move secrets to environment variables or a secrets manager;
reference them indirectly in config.

**CHAP-SEC-002 — Secrets in a git-tracked or world-shared path (High)**
OWASP: LLM06.
Detects config/secret files inside a git repo (and not git-ignored) or in a
shared/synced directory.
Heuristic: presence of `.git` above the config with the file not matched by
`.gitignore`.
Remediation: git-ignore secret files; rotate any key that may have been
committed.

**CHAP-SEC-003 — Overly permissive file permissions (Medium)**
OWASP: LLM06.
Detects secret/config files readable by group/other.
Heuristic: on POSIX, file mode broader than `0600` (or `0700` for dirs).
Remediation: `chmod 600` the file; restrict the directory.

**CHAP-SEC-004 — Secrets likely to reach logs (Medium)**
OWASP: LLM06.
Detects logging config set to verbose/debug while secret-bearing channels are
active, or log paths that are world-readable.
Remediation: raise log level; redact secrets; restrict log file permissions.

### Category B — Excessive agency & permissions

**CHAP-AGY-001 — Unrestricted shell execution (Critical)**
OWASP: LLM08 (Excessive Agency).
Detects skills/tools that can run arbitrary shell commands with no allowlist.
Heuristic: skill source or manifest exposing a shell/exec/spawn capability
without a command allowlist or confirmation gate.
Remediation: constrain to an explicit allowlist; require confirmation for
shell actions; sandbox execution.

**CHAP-AGY-002 — Unrestricted filesystem access (High)**
OWASP: LLM08.
Detects tools that can read/write outside a designated workspace directory.
Heuristic: file tools with no path scoping / root set to `/` or the home dir.
Remediation: scope file access to a sandbox directory; deny path traversal.

**CHAP-AGY-003 — Destructive/irreversible actions without confirmation (High)**
OWASP: LLM08.
Detects tools that can delete data, send messages, spend money, or make
irreversible changes with no human-in-the-loop gate.
Heuristic: capability flags/keywords (delete, send, transfer, purchase, deploy)
without a confirmation setting.
Remediation: require explicit confirmation for high-impact actions; add dry-run.

**CHAP-AGY-004 — Broad network egress from tools (Medium)**
OWASP: LLM08 / LLM06.
Detects tools permitted to call arbitrary external endpoints.
Heuristic: HTTP-capable tools with no domain allowlist.
Remediation: allowlist destinations; log outbound calls.

### Category C — Supply chain & skill provenance

**CHAP-SUP-001 — Skills from unverified sources (High)**
OWASP: LLM05 (Supply Chain).
Detects skills installed from arbitrary URLs, unpinned refs, or unknown authors.
Heuristic: skill metadata pointing to non-pinned git refs, raw URLs, or missing
provenance.
Remediation: pin versions/commits; prefer reviewed sources; verify authors.

**CHAP-SUP-002 — No integrity verification (Medium)**
OWASP: LLM05.
Detects skills/deps installed without a lockfile or hash verification.
Heuristic: missing lockfile in a skill that has dependencies.
Remediation: commit lockfiles; enable integrity checks.

**CHAP-SUP-003 — Known-vulnerable dependencies (High)**
OWASP: LLM05.
Detects dependency manifests inside skills with known-vulnerable versions.
Heuristic (v1): flag presence of manifests and surface them for `npm audit`;
optionally integrate an offline advisory check as a stretch goal. **Do not**
make outbound calls to an advisory API in v1 (violates the no-network rule);
instead report which manifests exist and instruct the user to run `npm audit`.
Remediation: update dependencies; remove unused ones.

**CHAP-SUP-004 — Dangerous install patterns (Medium)**
OWASP: LLM05.
Detects skills whose setup runs `curl | bash`, installs system package managers,
or requires broad system tooling.
Heuristic: scan skill install scripts/docs for `curl ... | bash`, `sudo`,
package-manager bootstrap commands.
Remediation: review install scripts; prefer vetted, minimal setup.

### Category D — Prompt-injection surface

**CHAP-INJ-001 — Untrusted input flows straight to the model (High)**
OWASP: LLM01 (Prompt Injection).
Detects inbound message channels whose content reaches the agent prompt with no
marking, filtering, or trust boundary.
Heuristic: active channels + no configured input handling / trust separation.
Remediation: mark untrusted content; separate instructions from data; filter.

**CHAP-INJ-002 — Tool output treated as trusted (Medium)**
OWASP: LLM02 (Insecure Output Handling).
Detects tool/skill outputs fed back into the model or executed without
validation.
Heuristic: chains where a tool's output can trigger another tool with no
validation step.
Remediation: validate/escape tool output; don't auto-execute model output.

**CHAP-INJ-003 — Actions triggerable by inbound messages without allowlist (High)**
OWASP: LLM01 / LLM08.
Detects that any inbound message can invoke high-impact tools.
Heuristic: no mapping restricting which channels/senders can trigger which tools.
Remediation: restrict tool invocation by channel/sender; allowlist commands.

**CHAP-INJ-004 — Auto-execution of links/commands from messages (High)**
OWASP: LLM01.
Detects settings that auto-open links or auto-run commands found in messages.
Heuristic: auto-execute / auto-follow flags enabled.
Remediation: disable auto-execution; require confirmation.

### Category E — Exposure & network posture

**CHAP-NET-001 — Gateway bound beyond localhost (Critical)**
OWASP: LLM06 / general.
Detects the gateway daemon listening on `0.0.0.0` or a public interface.
Heuristic: bind address not `127.0.0.1` / `localhost`.
Remediation: bind to localhost; put anything remote behind a tunnel with auth.

**CHAP-NET-002 — Missing/weak auth on the gateway control API (High)**
OWASP: general.
Detects the control API/port with no token or a default/empty token.
Heuristic: missing auth config, default token, or empty credential.
Remediation: require a strong token; rotate defaults.

**CHAP-NET-003 — Plaintext transport where sensitive (Medium)**
OWASP: general.
Detects sensitive endpoints configured without TLS where applicable.
Remediation: enable TLS; disable plaintext fallbacks.

### Category F — Observability & recoverability

**CHAP-OBS-001 — No audit log of agent actions (Medium)**
OWASP: LLM08-adjacent.
Detects that tool invocations / actions are not logged.
Remediation: enable an append-only action log.

**CHAP-OBS-002 — Sensitive data in plaintext logs (Medium)**
OWASP: LLM06.
Detects log config that records message bodies / secrets unredacted.
Remediation: redact sensitive fields; restrict log access.

**CHAP-OBS-003 — No kill switch / revocation path (Low)**
OWASP: general.
Detects absence of a documented quick way to stop the agent and revoke access.
Remediation: document a kill switch; script credential revocation.

> **Extensibility requirement:** adding a new check must mean adding one module
> under `src/checks/<category>/` and registering it in `checks/index.ts` — no
> changes to the engine. Design for this from the start.

---

## 8. Input & discovery behavior

- Accept a target path argument: `chaperone scan <path>` where `<path>` is the
  agent's root/config directory. If omitted, probe a small list of known default
  locations and report which was used.
- Discovery must be **defensive**: wrap every file read in error handling; if a
  file is missing/unparseable, record it in an `inspected`/`skipped` summary
  rather than throwing.
- Never follow symlinks outside the target root. Never read outside the target
  path except to check for an ancestor `.git` (CHAP-SEC-002), and even then only
  read directory existence and `.gitignore`, nothing else.
- Produce a normalized `AgentModel` (defined with zod in `model/types.ts`)
  containing: config data (secrets masked), skills list with parsed metadata and
  capabilities, file-permission facts, gateway/network settings, logging config,
  and the inspected/skipped inventory.

---

## 9. Output & reporting

Every reporter receives `Finding[]` plus scan metadata (target, timestamp,
inspected/skipped inventory, tool version).

A **Finding** contains: check ID, title, severity, category, OWASP mapping,
a human-readable message, the location (file + path/line where possible, with
secrets masked), and remediation text.

- **Console reporter (default):** grouped by severity (Critical first), color
  coded, with a summary line and an overall posture score. Must be readable on a
  plain terminal (degrade gracefully with `--no-color`).
- **JSON reporter (`--format json`):** the full structured result, schema-stable,
  suitable for automation. Define and document the schema with zod.
- **SARIF reporter (`--format sarif`):** SARIF 2.1.0 so results can be uploaded
  to GitHub code scanning. Map severity to SARIF levels.
- **Exit codes:** `0` = no findings at/above the fail threshold; non-zero when
  findings meet the `--fail-on <severity>` threshold (default: `high`). This lets
  Chaperone run in CI.

**Posture score:** a simple, documented formula (e.g. start at 100, subtract
weighted points per finding by severity, floor at 0). Show the score and a
letter/band. Keep the formula transparent in `CHECKS.md`.

---

## 10. CLI design

```
chaperone scan [path]           Scan an agent installation
  --format <console|json|sarif> Output format (default: console)
  --fail-on <severity>          Min severity for non-zero exit (default: high)
  --no-color                    Disable colored output
  --only <ids>                  Run only the listed check IDs (comma-separated)
  --skip <ids>                  Skip the listed check IDs
  --output <file>               Write report to a file instead of stdout

chaperone checks                List all available checks (id, title, severity)
chaperone version               Print version
```

Good defaults so `chaperone scan` with no flags does the right thing on a typical
install.

---

## 11. The check & engine model

- `Severity` is an ordered enum. `severity.ts` provides comparison + scoring.
- A `Check` is `{ id, title, severity, category, owasp, run(model): Finding[] }`.
- The engine imports all checks from `checks/index.ts`, applies `--only`/`--skip`
  filters, runs each `run(model)`, catches per-check errors (a broken check must
  not crash the scan — record it as an internal error finding), and returns
  aggregated results.
- Checks are **pure**: no file I/O, no network, deterministic given a model.

---

## 12. Build phases (execute in order)

**Phase 0 — Scaffold.** Init repo, TypeScript strict, ESLint/Prettier, test
runner, CI config, empty CLI that prints help. Commit. *Runnable check:* `--help`
works, lint and empty test suite pass.

**Phase 1 — Discovery + model.** Implement config location, parsing into
`AgentModel` (zod), and the inspected/skipped inventory. Add the two fixtures
(vulnerable + clean) as data to develop against. *Runnable check:* `chaperone
scan test/fixtures/vulnerable-agent` prints a parsed inventory (no checks yet).

**Phase 2 — Engine + 3 flagship checks.** Build the engine and implement
**CHAP-SEC-001** (plaintext secrets), **CHAP-AGY-001** (unrestricted shell), and
**CHAP-NET-001** (gateway exposed). Console reporter. Tests for all three.
*Runnable check:* scanning the vulnerable fixture reports exactly these findings;
scanning the clean fixture reports none.

**Phase 3 — Full check set.** Implement every remaining check in Section 7, each
with fixtures and tests. Keep `CHECKS.md` in sync. *Runnable check:* full check
catalog runs; expected findings match on both fixtures.

**Phase 4 — Reporters + exit codes + score.** Add JSON and SARIF reporters,
`--fail-on`, posture score, and file output. *Runnable check:* all three formats
validate; CI-style exit codes behave.

**Phase 5 — Hardening & UX.** Error handling polish, `--only`/`--skip`,
`--no-color`, `checks` subcommand, helpful messages when nothing is found.

**Phase 6 — Docs.** README (what/why/install/usage/example output), `CHECKS.md`
catalog, `DECISIONS.md` finalized, and a short "security & ethics" section
(Section 14) copied into the README.

Each phase ends with: build ✅, lint ✅, tests ✅, runs on both fixtures ✅, commit.

---

## 13. Testing strategy

- **Fixtures.** `test/fixtures/vulnerable-agent/` is a deliberately insecure but
  *inert* sample install: fake/dummy secrets (clearly marked `EXAMPLE`/`dummy`,
  never real), a skill with unrestricted shell, a gateway bound to `0.0.0.0`,
  etc. `test/fixtures/clean-agent/` is a hardened equivalent that should yield no
  findings. These double as documentation of what good and bad look like.
- **Per-check tests.** For every check: one test asserting it fires on the
  vulnerable fixture (right ID, severity, location) and one asserting it stays
  silent on the clean fixture. This gives explicit true-positive / true-negative
  coverage and guards against false positives, which are what kill trust in a
  scanner.
- **Discovery tests.** Malformed config, missing files, unreadable paths — assert
  graceful degradation, not crashes.
- **Reporter tests.** JSON validates against the schema; SARIF validates against
  SARIF 2.1.0 shape; exit codes match `--fail-on`.
- **No real secrets, ever**, in fixtures or tests. Use obvious dummies.

---

## 14. Security & ethics guardrails for Chaperone itself

These are hard requirements, not suggestions:

1. **Read-only.** Chaperone must never write to, modify, move, or delete any file
   in the target installation.
2. **No network.** Chaperone must make no outbound network connections during a
   scan. (This is also why CHAP-SUP-003 defers to `npm audit` rather than calling
   an advisory API in v1.)
3. **No exfiltration.** Anything Chaperone reads stays local. Reports are written
   only where the user directs. Secrets are masked in all output.
4. **Defensive framing only.** Chaperone identifies weaknesses in the user's own
   setup so they can fix them. It must not include exploitation, attack, or
   message-sending capabilities. If a future feature would cross into actively
   attacking an agent, it belongs in a separate, clearly-scoped project (see
   Section 16), not here.
5. **Clear provenance in output.** The report states what was and wasn't
   inspected, so users don't over-trust an incomplete scan.

State these guardrails in the README.

---

## 15. Documentation deliverables

- **README.md**: one-paragraph pitch; the problem; install; quickstart
  (`chaperone scan`); example console output; formats and CI usage; the
  security & ethics section; contributing notes.
- **CHECKS.md**: the full catalog — every check ID, title, severity, OWASP
  mapping, what it detects, and remediation. Keep it in sync with code.
- **DECISIONS.md**: dependency and design rationale accumulated during the build.

---

## 16. Stretch goals / future (do NOT build in v1)

- **HTML report** with a shareable summary.
- **Config file** for custom severities and per-check tuning.
- **Offline advisory database** for CHAP-SUP-003 (still no live network).
- **Chaperone-as-a-skill**: package it so it can run inside the agent ecosystem
  it audits and surface its own report.
- **Companion project (separate repo):** a *prompt-injection test harness* that
  actively probes an agent — this is intentionally kept out of Chaperone to keep
  Chaperone unambiguously defensive.

---

## 17. Definition of done for v1

- `chaperone scan` runs on a real or fixture install and produces a clear,
  prioritized report.
- All checks in Section 7 are implemented, each with true-positive and
  true-negative tests passing.
- Console, JSON, and SARIF reporters work; exit codes honor `--fail-on`.
- The vulnerable fixture yields the expected findings; the clean fixture yields
  none.
- README, CHECKS.md, and DECISIONS.md are complete.
- Lint and the full test suite pass; the repo builds from a clean checkout.
- All Section 14 guardrails hold (read-only, no network, secrets masked).