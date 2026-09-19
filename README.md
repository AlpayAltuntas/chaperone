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
chaperone fix CHAP-SEC-001 ~/clawd --dry-run   # guided remediation — see below; NEVER run implicitly by scan
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
chaperone scan ~/clawd --format html --output report.html   # a shareable, self-contained report
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
Scanned at 2026-09-19T20:23:15.771Z — chaperone v0.1.0

CRITICAL (5)

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

  ... 3 more critical-severity findings ...

HIGH (20)

  [CHAP-SEC-001] Plaintext secrets in config
    Config field 'llm.api_key' holds a literal secret value (sk-…wxyz) instead of an environment-variable reference.
    Location: ~/clawd/config.yaml (llm.api_key)
    OWASP: LLM06: Sensitive Information Disclosure
    Remediation: Move this value to an environment variable or a secrets manager and reference it indirectly in config (e.g. ${VAR} or env:VAR).

  ... 19 more high-severity findings ...

MEDIUM (18)  LOW (1)  ...

Summary: 44 findings (5 critical, 20 high, 18 medium, 1 low, 0 info) — posture score 0/100 (F)
Inspected 18 paths, skipped 0.
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

| Flag                          | Effect                                                                       | Env var                   |
| ----------------------------- | ---------------------------------------------------------------------------- | ------------------------- |
| `--format <format>`           | `console` (default, colored), `json`, `sarif`, `markdown`, `gha`, or `html`  | `CHAPERONE_FORMAT`        |
| `--fail-on <severity>`        | Minimum severity for a non-zero exit code (default: `high`)                  | `CHAPERONE_FAIL_ON`       |
| `--output <file>`             | Write the report to a file instead of stdout                                 | `CHAPERONE_OUTPUT`        |
| `--only <ids>`                | Run only the listed check IDs (comma-separated)                              |                           |
| `--skip <ids>`                | Skip the listed check IDs (comma-separated)                                  |                           |
| `--only-category <cats>`      | Display filter: only show findings in these categories (comma-separated)     | `CHAPERONE_ONLY_CATEGORY` |
| `--skip-category <cats>`      | Display filter: hide findings in these categories (comma-separated)          | `CHAPERONE_SKIP_CATEGORY` |
| `--min-severity <severity>`   | Display filter: only show findings at or above this severity                 | `CHAPERONE_MIN_SEVERITY`  |
| `--quiet`                     | One compact line per finding (id + severity) instead of full detail          |                           |
| `--summary-only`              | Print only the summary line and posture score, no per-finding detail         |                           |
| `--no-color`                  | Disable colored console output                                               |                           |
| `--config <file>`             | Suppression/override config file (default: `./.chaperonerc.json` if present) | `CHAPERONE_CONFIG`        |
| `--baseline <file>`           | A prior saved JSON report — report (and fail on) only findings new since it  | `CHAPERONE_BASELINE`      |
| `--profile <profile>`         | Discovery profile: `default` (fictional format) or `mcp` (real MCP config)   | `CHAPERONE_PROFILE`       |
| `--all <pattern>`             | Scan every immediate subdirectory of a parent, one aggregate report          | `CHAPERONE_ALL`           |
| `--docker <container[:path]>` | Scan a container's filesystem via `docker cp` (read-only)                    | `CHAPERONE_DOCKER`        |
| `--plugin <path>`             | Load a third-party check module (repeatable) — no sandboxing, trust it fully |                           |

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

### Suppressions & overrides (`.chaperonerc.json`)

Drop a `.chaperonerc.json` in the current directory (or pass `--config
<file>` / set `CHAPERONE_CONFIG`) to reclassify or suppress specific
findings project-wide, instead of repeating `--skip`/`--fail-on` flags on
every invocation:

```json
{
  "severityOverrides": { "CHAP-SUP-003": "low" },
  "ignore": [
    { "checkId": "CHAP-NET-002", "reason": "internal-only gateway", "expires": "2026-12-31" }
  ],
  "disabledChecks": ["CHAP-OBS-003"],
  "scoreWeights": { "medium": 10 }
}
```

- `severityOverrides` — reclassify a check's severity (e.g. demote a
  finding you've accepted as lower-risk). Unlike `--only-category`/
  `--skip-category`/`--min-severity`, this is a **real** reclassification:
  it feeds `--fail-on` and the posture score, not just what's displayed.
- `ignore` — suppress a check's findings entirely. An optional `expires`
  (ISO date) makes the suppression time-limited: once past, the finding
  reappears and Chaperone prints a warning instead of silently dropping
  it forever, so a suppression can't outlive the reason it was added for.
- `disabledChecks` — skip the listed checks entirely (equivalent to
  `--skip`, merged with any `--skip` flag also passed).
- `scoreWeights` — override the per-severity posture-score deduction
  weights (default: critical 25, high 15, medium 7, low 3, info 0).

An unknown check ID in `severityOverrides`/`ignore` prints a warning
(the suppression is likely stale after an upgrade, not worth failing the
whole scan over); an unknown ID in `disabledChecks` is treated like an
unknown `--skip` ID and fails hard, since that's a more likely direct
typo.

### Baseline / diff mode (`--baseline`)

Adopting Chaperone on an existing, imperfect install usually means
findings you already know about and aren't fixing today. `--baseline`
reports (and fails the build on) only what's new since a prior scan,
instead of making you either fix everything on day one or turn
`--fail-on` off entirely:

```bash
# Capture a baseline once...
chaperone scan ~/clawd --format json --output baseline.json

# ...then every later scan only reports/fails on genuinely new findings.
chaperone scan ~/clawd --baseline baseline.json
```

A baseline file is just a saved JSON report (`--format json --output
<file>`) — the schema already supports this for free, no separate
baseline format. "Same finding" is matched on check ID, file path,
location detail, and message, deliberately **not** line number — an
unrelated edit shifting lines elsewhere in the file shouldn't make an
unchanged finding look new. As findings actually get fixed, re-capture
the baseline to keep it current.

### Discovery profiles (`--profile`)

Chaperone's default profile targets a fictional, documented
Clawdbot/Moltbot/OpenClaw-style config shape (see [Known
limitations](#known-limitations)). `--profile mcp` (or `CHAPERONE_PROFILE=mcp`)
switches discovery to a **real** config shape instead — the [MCP (Model
Context Protocol)](https://modelcontextprotocol.io) server config used by
Claude Desktop, Claude Code, and other MCP clients
(`.mcp.json`/`mcp.json`/`claude_desktop_config.json`, a top-level
`{"mcpServers": {"<name>": {...}}}` object):

```bash
chaperone scan --profile mcp .            # looks for .mcp.json in the current directory
chaperone scan --profile mcp ~/my-project # or an explicit directory
```

The `mcp` profile maps each configured MCP server onto the same
`AgentModel` the default profile produces, so the existing check catalog
runs against it — but only the checks whose heuristic genuinely applies
to an MCP config actually fire: `CHAP-SEC-001` (a literal secret in a
server's `env` block instead of an env-var reference), `CHAP-SEC-003`
(the config file itself being group/other-readable), and `CHAP-SUP-001`
(a server launched from an unpinned package version, e.g. `npx -y
<pkg>` with no `@<version>` pin). Checks with no MCP equivalent —
gateway/channel/trust config, a skill's own source code — correctly stay
silent rather than being forced onto a shape they don't fit; see
`DECISIONS.md`, Phase 17.

### Multi-root batch scanning (`--all`)

Scan every install under one parent directory in a single run, producing
one aggregate report:

```bash
chaperone scan --all '~/agents/*' --format json    # quote it — your shell would otherwise expand the glob first
```

`--all` supports exactly one shape: a pattern ending in `/*` expands to
every immediate subdirectory of the parent (not a general glob engine —
no `**`, no character classes); a pattern with no trailing `/*` is
treated as a single directory. `--fail-on` fails the build if **any**
target trips it. `--format json`/`--format sarif` aggregate as one JSON
array / one multi-run SARIF document respectively — still a single,
machine-parseable file; every other format prints one
`===== Target N/M: <path> =====`-separated section per install.
`--output <file>` writes one combined file, not N separate ones.

### Docker-aware scanning (`--docker`)

Scan a container's filesystem directly, without needing a shell (or
anything at all) running inside it:

```bash
chaperone scan --docker my-agent-container:/agent-root
chaperone scan --docker my-agent-container   # defaults to the container's root
```

Reads the container via `docker cp` (read-only, works on a stopped
container too) into a throwaway local temp directory, then runs the
exact same discovery pipeline used for a local install — cleaned up
automatically when the scan finishes. Requires the `docker` CLI on
`PATH` and a reachable daemon; **not** a live `docker exec` introspection
of the running process — see `DECISIONS.md`, Phase 20 for what that
means for env-var-injected secrets (`docker-compose.yml`'s
`environment:`/`env_file:`) that this doesn't (yet) resolve.

### Plugins (`--plugin`)

**A plugin is arbitrary code with full access to `AgentModel`, loaded
and run with no sandboxing whatsoever.** Loading one means trusting it
exactly as much as any other dependency you'd `npm install` and run —
only load a plugin you've read and trust. This is entirely opt-in:
nothing is ever loaded without you naming it explicitly, and Chaperone
prints an unmissable warning to stderr every time one is.

```bash
chaperone scan ~/clawd --plugin ./my-checks.cjs           # repeatable — pass --plugin more than once
```

Or via `.chaperonerc.json`'s `plugins` array (merged with any `--plugin`
flags, config-file entries first):

```json
{ "plugins": ["./my-checks.cjs"] }
```

A plugin module's default export must be a single object shaped like
the `Check` interface (`src/engine/types.ts`) — `id`, `title`,
`severity`, `category`, `owasp`, `detects`, `heuristic`, `remediation`,
and a `run(model)` function — or an array of them:

```js
// my-checks.cjs — plain CommonJS (module.exports), not ESM: plugins are
// loaded synchronously via require(), so `chaperone scan` never needs to
// become an async CLI just to support them.
module.exports = {
  id: 'CHAP-CUSTOM-001',
  title: 'Skill name flagged by organization policy',
  severity: 'medium',
  category: 'supply-chain',
  owasp: 'LLM05: Supply Chain',
  detects: "A skill whose name contains 'experimental'.",
  heuristic: "Skill name (case-insensitive) contains 'experimental'.",
  remediation: 'Rename the skill or get security sign-off.',
  run(model) {
    return model.skills
      .filter((skill) => skill.name.toLowerCase().includes('experimental'))
      .map((skill) => ({
        checkId: 'CHAP-CUSTOM-001',
        title: 'Skill name flagged by organization policy',
        severity: 'medium',
        category: 'supply-chain',
        owasp: 'LLM05: Supply Chain',
        message: `Skill '${skill.name}' matches the 'experimental' naming policy.`,
        location: { filePath: skill.manifestPath, line: null, detail: skill.name },
        remediation: 'Rename the skill or get security sign-off.',
      }));
  },
};
```

See `test/fixtures/plugins/samplePlugin.cjs` for the real version of
this example. A plugin check runs alongside every built-in one — it
feeds `--fail-on` and the posture score identically, and a check ID
colliding with a built-in (or another plugin's) check is a hard error,
never a silent override.

### Guided remediation (`chaperone fix`)

**A separate command, deliberately — never run during `scan`.**
`chaperone scan`'s read-only guardrail (see [Security &
ethics](#security--ethics)) applies to the scanner; `chaperone fix` is a
materially different trust posture, named and packaged distinctly on
purpose so "Chaperone found this" and "Chaperone changed this" are never
confusable:

```bash
chaperone fix CHAP-SEC-001 ~/clawd                    # always prints the proposed change; writes nothing
chaperone fix CHAP-SEC-001 ~/clawd --dry-run --write  # review it, then actually apply it
```

`--write` **requires** `--dry-run` to also be passed — the proposed
change is always shown immediately before anything is written, in that
order, every time; there is no way to write without it. Only `CHAP-SEC-001`
has a working fixer in this release (replaces a literal secret in
`config.yaml`/`.json` with a `${SUGGESTED_ENV_VAR_NAME}` reference,
preserving the rest of the file's formatting and comments via a
round-trip-preserving YAML edit) — a deliberately narrow v1, not parity
with the full check catalog. The proposed change is always a masked,
field-level summary (`llm.api_key: sk-…wxyz -> ${LLM_API_KEY}`), never a
raw line diff of file text, so a real secret is never printed even in
the "before" column.

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
- **`npm audit`** / **[Snyk](https://snyk.io)** — real, live, comprehensive
  dependency vulnerability databases. `CHAP-SUP-003` (Phase 18) matches
  dependencies against a small, bundled, _offline_ snapshot of known
  advisories for a curated set of well-known packages (refreshed
  periodically out-of-band, never fetched live during a scan) — a real
  match against real data, but nowhere near `npm audit`'s live coverage
  of the whole npm ecosystem. Run `npm audit` too; Chaperone doesn't
  replace it.

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
- **`CHAP-SUP-003`'s offline vulnerability snapshot is small and
  curated, not comprehensive.** It only tracks a handful of well-known
  npm packages (see `src/checks/shared/vulnDb.ts`), refreshed
  periodically out-of-band via `npm run refresh:vulndb` — never fetched
  live during a scan (see [Security & ethics](#security--ethics)). A
  vulnerable dependency outside that list is invisible to it; run `npm
audit` for real, comprehensive coverage.
- **A few heuristics are static proxies, not confirmed findings** — most
  notably `CHAP-INJ-002` ("tool output treated as trusted"), which flags
  the _shape_ of a risky pattern (a skill that both ingests external data
  and can run shell commands) rather than tracing real data flow.
- **Python skill capability detection is regex-based, not AST-based.**
  JS/TS skills get real parse-tree analysis (import/require binding
  resolution, aliased-import tracking — see `CHECKS.md`); `.py` files
  (Phase 16) get a simpler pattern match over raw source text —
  `subprocess`/`os.system`/`eval`/`requests.*` and similar. It can
  false-positive on a pattern inside a comment/string and false-negative
  on an unconventional spelling (e.g. `delete_file` doesn't match the
  standalone word `delete`) — a documented v1-equivalent limitation for
  Python, not held to JS/TS's AST-based bar.
- **The posture score isn't shown in console output yet** — only in the
  JSON report's `summary.score`/`summary.band`. See `CHECKS.md`.

## Security & ethics

These are hard requirements Chaperone holds itself to, not suggestions:

1. **Read-only.** `chaperone scan` never writes to, modifies, moves, or
   deletes any file in the target installation — including a `--docker`
   target's container: `docker cp` only ever reads from it. The one
   exception in this entire codebase is the separate, explicitly opt-in
   `chaperone fix` command (see [Guided
   remediation](#guided-remediation-chaperone-fix) above) — and even
   there, nothing is ever written without `--write`, which itself
   requires `--dry-run` to also be passed, so the proposed change is
   always shown immediately before anything is written. `chaperone
scan` itself has no write capability at all, regardless of any flag.
2. **No network.** Chaperone makes no outbound network connections during
   `chaperone scan` — verified by a test that fails if one occurs (see
   `test/scan/noNetworkCalls.test.ts`). `CHAP-SUP-003` matches
   dependencies against a small, bundled, offline snapshot rather than a
   live advisory API for exactly this reason. The one deliberate
   exception in this whole codebase is `npm run refresh:vulndb` — an
   explicit, maintainer-run, out-of-band script (never part of `scan`,
   `test`, `build`, or CI) that refreshes that snapshot from OSV.dev.
   `--docker` talks to the local Docker daemon over its local socket to
   read a container's filesystem — not an outbound connection to the
   internet, the thing this guarantee is actually about — but it is the
   one place `chaperone scan` itself spawns a subprocess at all; see
   `DECISIONS.md`, Phase 20.
3. **No exfiltration.** Anything Chaperone reads stays local. Reports are
   written only where you direct them. Secrets are masked in all output.
4. **Defensive framing only.** Chaperone identifies weaknesses in your own
   setup so you can fix them. It has no exploitation, attack, or
   message-sending capabilities, and won't grow any — an active
   prompt-injection test harness is intentionally a separate,
   clearly-scoped project, not this one.
5. **Clear provenance in output.** Every report states what was and
   wasn't inspected, so you don't over-trust an incomplete scan.
6. **Plugins are a stated exception, not a loophole.** `--plugin` loads
   and runs arbitrary third-party code with full `AgentModel` access —
   the guarantees above are what Chaperone _itself_ holds to; a plugin
   you explicitly load is a separate trust decision you're making, the
   same as installing any other dependency. Entirely opt-in, with an
   unmissable warning every time one loads.

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

**Refreshing the offline vulnerability snapshot** (`CHAP-SUP-003`,
`src/checks/shared/vulnDb.ts`): run `npm run refresh:vulndb`. This is the
one script in the repo that makes an outbound network call (to
[OSV.dev](https://osv.dev)) — it is never run by `scan`, `test`, `build`,
or CI. Review the regenerated file's diff like any other source change
before committing it.

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
