# Chaperone

[![CI](https://github.com/AlpayAltuntas/chaperone/actions/workflows/ci.yml/badge.svg)](https://github.com/AlpayAltuntas/chaperone/actions/workflows/ci.yml)

Chaperone is a command-line security scanner for self-hosted personal AI
agents. It audits an agent's local install — its config, its skills/plugins,
its gateway — and produces a prioritized, OWASP-mapped report of what's
dangerous, why it matters, and how to fix it. Think of it as a linter for
the security posture of your personal AI agent.

## The problem

Self-hosted personal AI agents (Clawdbot/Moltbot/OpenClaw-style assistants,
and similar) have exploded in popularity. They run locally, connect to your
messaging apps, hold persistent memory, and — crucially — **execute real
actions** through a skills/plugin system: running shell commands, reading
and writing files, calling external APIs.

That combination — an LLM, broad local access, and untrusted inbound
messages — is a serious security exposure that almost nobody audits
systematically. Secrets sit in plaintext configs, skills come from
unverified sources, gateways get exposed beyond localhost, and inbound
messages can drive tool execution (prompt injection). Chaperone scans your
own install and tells you what to fix.

**Chaperone is a defensive tool.** It audits the setup you point it at, on
your own machine, read-only. It is not an exploitation tool. See
[Security & ethics](#security--ethics) below.

## Install

```bash
npm install -g @alpay_altuntas/chaperone
chaperone scan ~/clawd
```

Or run it from a clone instead:

```bash
git clone https://github.com/AlpayAltuntas/chaperone.git
cd chaperone
npm install
npm run build
node dist/cli.js scan ~/clawd   # or: npm link, then use `chaperone` directly
```

Requires Node.js ≥ 20.

## Quickstart

```bash
chaperone scan <path-to-agent-install>
```

`<path>` is the agent's root/config directory — wherever its `config.yaml`
(or `.yml`/`.json`) lives. If you omit it, Chaperone probes a short list of
illustrative default locations (`~/.clawd`, `~/clawd`, `~/.config/clawdbot`,
and similar — see `CHECKS.md`/`DECISIONS.md`) and tells you which one it
used, or that none were found.

```bash
chaperone checks                # list every check Chaperone runs (id, title, severity)
chaperone explain CHAP-SEC-001  # full detail for one check: detects, heuristic, remediation
chaperone version               # print the installed version
chaperone scan --help           # full flag reference
```

## How to use

**1. Point it at an install.**

```bash
chaperone scan ~/clawd
```

Pass the agent's root/config directory explicitly — this is the reliable
way to use Chaperone. Omit the path and it probes a short list of
illustrative default locations instead (see Quickstart above).

**2. Read the report.** Findings are grouped by severity, critical first.
Each one gives you everything you need to act without opening the code:
a check ID (`[CHAP-SEC-001]`), what's wrong, exactly where (file + a
config-key or skill-name detail, never a raw secret), the OWASP LLM
mapping, and concrete remediation. The summary line at the bottom counts
findings per severity and how many paths were inspected vs. skipped (and
why — see the "Skipped" section in the output if anything couldn't be
read).

**3. Narrow it down**, once you know what you're looking at:

```bash
chaperone scan ~/clawd --only CHAP-SEC-001,CHAP-NET-001   # just these checks
chaperone scan ~/clawd --skip CHAP-SUP-003                # everything except these
chaperone checks                                          # see every check ID first
```

**4. Pick an output format** depending on who's consuming it:

```bash
chaperone scan ~/clawd --format console    # for a human, in a terminal (default)
chaperone scan ~/clawd --format json       # for scripts/automation
chaperone scan ~/clawd --format sarif      # for GitHub code scanning
chaperone scan ~/clawd --format markdown   # for a PR comment (gh pr comment --body-file)
chaperone scan ~/clawd --format gha        # inline GitHub Actions annotations
```

**5. Save it instead of printing it:**

```bash
chaperone scan ~/clawd --format json --output report.json
```

`--output` also strips color from `--format console` reports automatically,
so a saved file never ends up full of ANSI codes. Use `--no-color` to do
the same for anything printed to a terminal that doesn't render color well.

**6. Gate a build on it.** `chaperone scan` exits non-zero whenever a
finding meets (or exceeds) `--fail-on` (default `high`) — or when it
couldn't locate an installation to scan at all, so "nothing was scanned"
is never mistaken for "nothing was found":

```bash
chaperone scan ~/clawd --fail-on critical   # only fail the build on criticals
```

See [Formats & CI usage](#formats--ci-usage) below for a full CI job
example.

## Example output

Running against a deliberately-insecure sample install
(`test/fixtures/vulnerable-agent` in this repo) looks like this (trimmed —
the real run reports 44 findings across all 29 checks):

```
Chaperone scan report
Target: ~/clawd
Scanned at 2026-09-15T16:30:35.304Z — chaperone v0.1.0

CRITICAL (4)

  [CHAP-AGY-001] Unrestricted shell execution
    Skill 'command-relay' can execute arbitrary shell commands with no detected command allowlist or confirmation gate.
    Location: ~/clawd/skills/command-relay/package.json (command-relay)
    OWASP: LLM08: Excessive Agency
    Remediation: Constrain the skill to an explicit command allowlist, require confirmation for shell actions, or sandbox its execution.

  [CHAP-NET-001] Gateway bound beyond localhost
    The gateway is bound to '0.0.0.0', not localhost, making it reachable from other hosts on the network.
    Location: ~/clawd/config.yaml (gateway.host)
    OWASP: LLM06 / general
    Remediation: Bind the gateway to 127.0.0.1/localhost; put anything that must be remote behind a tunnel with authentication.

  ... 2 more critical-severity findings ...

HIGH (17)

  [CHAP-SEC-001] Plaintext secrets in config
    Config field 'llm.api_key' holds a literal secret value (sk-…wxyz) instead of an environment-variable reference.
    Location: ~/clawd/config.yaml (llm.api_key)
    OWASP: LLM06: Sensitive Information Disclosure
    Remediation: Move this value to an environment variable or a secrets manager and reference it indirectly in config (e.g. ${VAR} or env:VAR).

  ... 16 more high-severity findings ...

MEDIUM (17)  LOW (1)  ...

Summary: 44 findings (4 critical, 17 high, 17 medium, 1 low, 5 info) — posture score 0/100 (F)
Inspected 16 paths, skipped 0.
```

Notice the secret value is masked (`sk-…wxyz`) — the real value is never
printed, anywhere, in any format.

Try it yourself against this repo's own fixtures:

```bash
chaperone scan test/fixtures/vulnerable-agent   # deliberately insecure sample
chaperone scan test/fixtures/clean-agent        # hardened sample
```

## Formats & CI usage

Full flag reference (see [How to use](#how-to-use) above for examples of
each):

| Flag                        | Effect                                                                   | Env var                   |
| --------------------------- | ------------------------------------------------------------------------ | ------------------------- |
| `--format <format>`         | `console` (default, colored), `json`, `sarif`, `markdown`, or `gha`      | `CHAPERONE_FORMAT`        |
| `--fail-on <severity>`      | Minimum severity for a non-zero exit code (default: `high`)              | `CHAPERONE_FAIL_ON`       |
| `--output <file>`           | Write the report to a file instead of stdout                             | `CHAPERONE_OUTPUT`        |
| `--only <ids>`              | Run only the listed check IDs (comma-separated)                          |                           |
| `--skip <ids>`              | Skip the listed check IDs (comma-separated)                              |                           |
| `--only-category <cats>`    | Display filter: only show findings in these categories (comma-separated) | `CHAPERONE_ONLY_CATEGORY` |
| `--skip-category <cats>`    | Display filter: hide findings in these categories (comma-separated)      | `CHAPERONE_SKIP_CATEGORY` |
| `--min-severity <severity>` | Display filter: only show findings at or above this severity             | `CHAPERONE_MIN_SEVERITY`  |
| `--quiet`                   | One compact line per finding (id + severity) instead of full detail      |                           |
| `--summary-only`            | Print only the summary line and posture score, no per-finding detail     |                           |
| `--no-color`                | Disable colored console output                                           |                           |

`--only-category`/`--skip-category`/`--min-severity` are **display
filters only** — they change what's printed, never what's checked or
whether the build fails. `--fail-on` always evaluates every finding that
actually ran, regardless of any display filter, so a filtered report can
never accidentally hide a real failure from CI. `--quiet` and
`--summary-only` are console-only and mutually exclusive.

Exit code is `0` when no finding meets the `--fail-on` threshold (and an
installation was actually found), `1` otherwise — including when Chaperone
couldn't locate an installation to scan at all, so a CI pipeline never
mistakes "nothing was scanned" for "nothing was found."

A minimal CI job that fails the build on high+ findings and uploads results
to GitHub code scanning:

```yaml
- name: Chaperone security scan
  run: |
    chaperone scan ~/clawd --format sarif --output chaperone.sarif --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: chaperone.sarif
```

Two lighter-weight GitHub-native alternatives, when the full code-scanning
upload flow is more than a given job needs:

```yaml
# Inline PR annotations, no upload step needed — GitHub parses these
# workflow commands live from the step's own output.
- run: chaperone scan ~/clawd --format gha --fail-on high

# Or post the findings as a PR comment.
- run: chaperone scan ~/clawd --format markdown --output report.md --fail-on high
- run: gh pr comment "$PR_NUMBER" --body-file report.md
  if: always()
  env:
    GH_TOKEN: ${{ github.token }}
```

## Checks

Chaperone runs 29 checks across six categories — secrets & credential
hygiene, excessive agency & permissions, supply chain & skill provenance,
prompt-injection surface, exposure & network posture, and observability &
recoverability. Every check maps to an OWASP LLM Top 10 category and ships
remediation guidance.

See **[CHECKS.md](CHECKS.md)** (generated from the check registry via `npm
run docs:checks` — see `improvement_plan.md` 4.2) for the full catalog and
the posture-score formula, `chaperone checks` for a quick id/title/severity
listing, or `chaperone explain <check-id>` for one check's full detail
from the terminal.

## How Chaperone relates to other tools

Chaperone isn't trying to replace generic secret/dependency scanners —
several already do parts of what the `CHAP-SEC-*`/`CHAP-SUP-*` categories
do, generically and well:

- **[gitleaks](https://github.com/gitleaks/gitleaks)** /
  **[trufflehog](https://github.com/trufflesecurity/trufflehog)** — generic
  secret scanning across any codebase, including git history. Chaperone's
  secret detection (`CHAP-SEC-001/002`) is narrower (config-file-shaped,
  no history scanning) but knows what an agent config file's fields mean
  (a `gateway.auth.token` vs. an arbitrary string).
- **`npm audit`** / **[Snyk](https://snyk.io)** — real, live dependency
  vulnerability databases. `CHAP-SUP-003` deliberately _doesn't_ try to
  compete here — it points you at `npm audit` rather than reimplementing
  it, because Chaperone makes no outbound network calls during a scan.

**What none of those tools cover, and what Chaperone actually exists
for**, is everything agent-specific: whether a skill can run arbitrary
shell commands with no allowlist (`CHAP-AGY-*`), whether inbound messages
can drive tool execution with no trust boundary (`CHAP-INJ-*`), and
whether the gateway bridging those messages is exposed or weakly
authenticated (`CHAP-NET-*`/`CHAP-OBS-*`). Run Chaperone _alongside_
those tools, not instead of them.

## Known limitations

Chaperone is a static, offline, v1 linter — not a substitute for a real
audit. Worth knowing before you trust its output:

- **No canonical config/manifest schema exists** for the fictional example
  agents this targets (Clawdbot/Moltbot/OpenClaw-style). The config and
  skill-manifest shape Chaperone expects is a documented, plausible
  convention, not a verified standard — see `DECISIONS.md`.
- **`CHAP-SUP-003`'s heuristic is deliberately weak.** Chaperone makes no
  outbound network calls (see below), so it can't check dependencies
  against a live vulnerability database. It surfaces every dependency
  manifest it finds and points you at `npm audit` — meaning it fires on a
  well-hardened install exactly as readily as an insecure one. This is a
  known, spec-mandated limitation, not a bug.
- **A few heuristics are static proxies, not confirmed findings** — most
  notably `CHAP-INJ-002` ("tool output treated as trusted"), which flags
  the _shape_ of a risky pattern (a skill that both ingests external data
  and can run shell commands) rather than tracing real data flow.
- **`.gitignore` matching (`CHAP-SEC-002`) covers a small subset** of real
  gitignore semantics — no `**`, no nested `.gitignore` files.
- **The posture score isn't shown in console output yet** — only in the
  JSON report's `summary.score`/`summary.band`. See `CHECKS.md`.

## Security & ethics

These are hard requirements Chaperone holds itself to, not suggestions:

1. **Read-only.** Chaperone never writes to, modifies, moves, or deletes
   any file in the target installation.
2. **No network.** Chaperone makes no outbound network connections during
   a scan. (This is also why `CHAP-SUP-003` defers to `npm audit` rather
   than calling an advisory API.)
3. **No exfiltration.** Anything Chaperone reads stays local. Reports are
   written only where you direct them. Secrets are masked in all output.
4. **Defensive framing only.** Chaperone identifies weaknesses in your own
   setup so you can fix them. It has no exploitation, attack, or
   message-sending capabilities, and won't grow any — an active
   prompt-injection test harness is intentionally a separate,
   clearly-scoped project, not this one.
5. **Clear provenance in output.** Every report states what was and
   wasn't inspected, so you don't over-trust an incomplete scan.

## Contributing

```bash
npm run lint          # ESLint
npm run format         # Prettier --check
npm run typecheck      # tsc over src/
npm run typecheck:tests # tsc over src/ + test/ (catches test-only type errors ESLint misses)
npm run build           # compile to dist/
npm test                # vitest
```

**Adding a new check** means adding one module under `src/checks/<category>/`
and registering it in `src/checks/index.ts` — the engine itself never
changes. Every check needs a true-positive fixture (fires) and a
true-negative fixture (stays silent); see `test/checks/` for the existing
pattern and `test/fixtures/{vulnerable,clean}-agent/` for the sample
installs. Update `CHECKS.md` to match.

**Before publishing** (or after any change to `src/cli.ts`), verify the
actual packaged binary, not just `npm test` — a real bug (the CLI silently
doing nothing once installed) only ever showed up this way, never in the
test suite:

```bash
npm run build
npm pack                                  # produces a real .tgz
mkdir -p /tmp/chaperone-pack-check && cd /tmp/chaperone-pack-check
npm init -y && npm install /path/to/chaperone/*.tgz
node node_modules/.bin/chaperone --version
node node_modules/.bin/chaperone scan /path/to/some/fixture
```

See **[DECISIONS.md](DECISIONS.md)** for the design rationale behind every
non-obvious choice made while building this.

## License

MIT
