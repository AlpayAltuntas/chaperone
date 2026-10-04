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

Requires Node.js ≥ 22.

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
chaperone check-update          # opt-in only — see below; NEVER run implicitly by any other command
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
the real run reports 39 findings across all 37 checks):

```
Chaperone scan report
Target: ~/clawd
Profile: default (detected)
Scanned at 2026-10-03T20:17:11.162Z — chaperone v0.4.0

CRITICAL (5)

  [CHAP-AGY-001] Unrestricted shell execution
    Skill 'command-relay' can execute arbitrary shell commands with no detected command allowlist or confirmation gate. Seen at index.js:9 (child_process.exec).
    Location: ~/clawd/skills/command-relay/index.js:9 (command-relay)
    OWASP: LLM08: Excessive Agency
    Remediation: Constrain the skill to an explicit command allowlist, require confirmation for shell actions, or sandbox its execution.

  [CHAP-NET-001] Gateway bound beyond localhost
    The gateway is bound to '0.0.0.0', not localhost, making it reachable from other hosts on the network.
    Location: ~/clawd/config.yaml:16 (gateway.host)
    OWASP: LLM06 / general
    Remediation: Bind the gateway to 127.0.0.1/localhost; put anything that must be remote behind a tunnel with authentication.

  ... 3 more critical-severity findings ...

HIGH (20)

  [CHAP-SEC-001] Plaintext secrets in config
    Config field 'llm.api_key' holds a literal secret value (sk-…wxyz) instead of an environment-variable reference.
    Location: ~/clawd/config.yaml:6 (llm.api_key)
    OWASP: LLM06: Sensitive Information Disclosure
    Remediation: Move this value to an environment variable or a secrets manager and reference it indirectly in config (e.g. ${VAR} or env:VAR).

  ... 19 more high-severity findings ...

MEDIUM (13)  LOW (1)  ...

Skipped (1):
  - (profile: default): checks not applicable to this profile: CHAP-SEC-009, CHAP-AGY-006, CHAP-AGY-007, CHAP-AGY-008, CHAP-SUP-008, CHAP-SUP-009

Summary: 39 findings (5 critical, 20 high, 13 medium, 1 low, 0 info) — posture score 0/100 (F)
Inspected 18 paths, skipped 1.
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

| Flag                          | Effect                                                                         | Env var                   |
| ----------------------------- | ------------------------------------------------------------------------------ | ------------------------- |
| `--format <format>`           | `console` (default, colored), `json`, `sarif`, `markdown`, `gha`, or `html`    | `CHAPERONE_FORMAT`        |
| `--fail-on <severity>`        | Minimum severity for a non-zero exit code (default: `high`)                    | `CHAPERONE_FAIL_ON`       |
| `--output <file>`             | Write the report to a file instead of stdout                                   | `CHAPERONE_OUTPUT`        |
| `--only <ids>`                | Run only the listed check IDs (comma-separated)                                |                           |
| `--skip <ids>`                | Skip the listed check IDs (comma-separated)                                    |                           |
| `--only-category <cats>`      | Display filter: only show findings in these categories (comma-separated)       | `CHAPERONE_ONLY_CATEGORY` |
| `--skip-category <cats>`      | Display filter: hide findings in these categories (comma-separated)            | `CHAPERONE_SKIP_CATEGORY` |
| `--min-severity <severity>`   | Display filter: only show findings at or above this severity                   | `CHAPERONE_MIN_SEVERITY`  |
| `--quiet`                     | One compact line per finding (id + severity) instead of full detail            |                           |
| `--summary-only`              | Print only the summary line and posture score, no per-finding detail           |                           |
| `--no-color`                  | Disable colored console output                                                 |                           |
| `--config <file>`             | Suppression/override config file (default: `./.chaperonerc.json` if present)   | `CHAPERONE_CONFIG`        |
| `--baseline <file>`           | A prior saved JSON report — report (and fail on) only findings new since it    | `CHAPERONE_BASELINE`      |
| `--profile <profile>`         | Discovery profile: `default`, `mcp`, or `claude-code` (auto-detected if unset) | `CHAPERONE_PROFILE`       |
| `--all <pattern>`             | Scan every immediate subdirectory of a parent, one aggregate report            | `CHAPERONE_ALL`           |
| `--docker <container[:path]>` | Scan a container's filesystem via `docker cp` (read-only)                      | `CHAPERONE_DOCKER`        |
| `--plugin <path>`             | Load a third-party check module (repeatable) — no sandboxing, trust it fully   |                           |

`--only-category`/`--skip-category`/`--min-severity` are **display
filters only** — they change what's printed, never what's checked or
whether the build fails. `--fail-on` always evaluates every finding that
actually ran, regardless of any display filter, so a filtered report can
never accidentally hide a real failure from CI. `--quiet` and
`--summary-only` are console-only and mutually exclusive.

Exit code is `0` when no finding meets the `--fail-on` threshold (and an
installation was actually found), `1` otherwise — including when Chaperone
couldn't locate an installation to scan at all, so a CI pipeline never
mistakes "nothing was scanned" for "nothing was found." An explicit path
counts as "nothing scanned" when it doesn't exist, is a file other than
the config file, or is a directory with neither a config file nor a
`skills/` directory (for `--profile mcp`: no parseable MCP config). Such
a report shows no posture score. Passing the config file itself
(`chaperone scan ~/clawd/config.yaml`) scans its directory.

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
baseline format. "Same finding" is matched on check ID, the file path
_relative to the scanned target_, and location detail. Deliberately left
out: the line number (an unrelated edit shifting lines shouldn't make an
unchanged finding look new), the message text (rewording in a later
Chaperone release shouldn't either), and the absolute path, so a baseline
captured on your laptop still matches the same install checked out
somewhere else in CI. As findings actually get fixed, re-capture the
baseline to keep it current.

### Discovery profiles (`--profile`)

Chaperone's default profile targets a fictional, documented
Clawdbot/Moltbot/OpenClaw-style config shape (see [Known
limitations](#known-limitations)). `--profile mcp` (or `CHAPERONE_PROFILE=mcp`)
switches discovery to a **real** config shape instead — the [MCP (Model
Context Protocol)](https://modelcontextprotocol.io) server config used by
Claude Desktop, Claude Code, Cursor, VS Code, and other MCP clients:

```bash
chaperone scan --profile mcp .                      # .mcp.json, mcp.json, claude_desktop_config.json, .vscode/mcp.json, .cursor/mcp.json
chaperone scan --profile mcp ~/.claude.json         # or any MCP config file directly
chaperone scan --profile mcp                        # current directory, then the user-level Claude Desktop/Cursor/Claude Code configs
```

Both the `mcpServers` key and VS Code's `servers` key are read, along with
the per-project servers in Claude Code's `~/.claude.json`. Each server
is mapped onto the same model the default profile produces, with
capabilities derived from how it's launched:

- A shell run with `-c` (`bash -c "…"`, `cmd /c`, `pwsh -Command`) is
  shell execution (`CHAP-AGY-001`), and its command string is checked for
  `curl … | sh` and friends (`CHAP-SUP-004`).
- The filesystem server rooted at `/`, `~`, `$HOME`, or a drive root is
  unscoped filesystem access (`CHAP-AGY-002`).
- `docker run`/`podman run` with `--privileged`, `--cap-add=ALL`, a host
  namespace, or a bind mount of `/`, the Docker socket, or `$HOME` is
  `CHAP-AGY-005`.
- A remote server on plaintext `http://` (not loopback) is
  `CHAP-NET-003`.
- A literal token in `env`, `headers`, or `args` is `CHAP-SEC-001`.
- An unpinned package (`npx -y <pkg>` with no `@<version>`) is
  `CHAP-SUP-001`.

Checks with no MCP equivalent (gateway, channel, and trust config) don't
run under this profile and are listed as not applicable. A config that
defines no servers is reported as nothing scanned.

#### Claude Code (`--profile claude-code`)

Reads Claude Code's own settings: `.claude/settings.json` (shared
project), `.claude/settings.local.json` (local), and, when no path is
given, `~/.claude/settings.json` (user). The project's `.mcp.json` is
analyzed as in the `mcp` profile. Settings-specific checks:

| Check          | Fires on                                                                                                                               |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `CHAP-AGY-006` | `permissions.defaultMode: "bypassPermissions"` (critical in user settings; low in project/local, where current Claude Code ignores it) |
| `CHAP-AGY-007` | an allow rule for every shell command (`Bash`, `Bash(*)`), or for an interpreter, downloader, or `rm`/`sudo` prefix (`Bash(python:*)`) |
| `CHAP-AGY-008` | an allow rule for every web fetch (`WebFetch`, `WebFetch(domain:*)`)                                                                   |
| `CHAP-SEC-009` | no `Read` deny rule for `.env` files or `~/.ssh`                                                                                       |
| `CHAP-SUP-008` | `enableAllProjectMcpServers: true`                                                                                                     |
| `CHAP-SUP-009` | a hook, `statusLine`, `fileSuggestion`, or `apiKeyHelper` command that pipes a download into a shell or uses `sudo`                    |

A literal secret in an `env` block is reported by `CHAP-SEC-001`. The
settings keys were checked against the Claude Code documentation on
2026-10-03; the schema evolves, so report anything that has drifted.

#### Auto-detection

Without `--profile` (or `CHAPERONE_PROFILE`), Chaperone picks the
profile from the files in the target: a `config.yaml`/`.yml`/`.json` or
`skills/` directory means `default`, `.claude/settings*.json` means
`claude-code`, and an MCP config (`.mcp.json`, `.vscode/mcp.json`, ...)
means `mcp`. The report header says `Profile: mcp (detected)`. If the
default format and another profile both match, the scan stops and asks
for `--profile`. If nothing matches, the `default` profile runs as
before.

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

### Checking for updates (`chaperone check-update`)

**Opt-in only — never run automatically, by `scan` or anything else.**

```bash
chaperone check-update
```

Queries the npm registry for the latest published version and compares
it against the one you're running; prints an install command if you're
behind, or confirms you're current. This is the one place in the whole
CLI that makes an outbound network call outside `npm run refresh:vulndb`
(see [Security & ethics](#security--ethics)) — and even here, only when
you explicitly ask for it.

A complete GitHub Actions workflow that fails the build on high+
findings, uploads results to GitHub code scanning, and keeps the HTML
report as a build artifact:

```yaml
name: chaperone
on: [push, pull_request]

permissions:
  contents: read
  security-events: write # upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 22
      - run: npm install -g @alpay_altuntas/chaperone

      - name: Chaperone security scan
        run: chaperone scan ./agent --format sarif --output chaperone.sarif --fail-on high

      - name: HTML report
        if: always()
        run: chaperone scan ./agent --format html --output chaperone.html --fail-on critical || true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: chaperone.sarif
          category: chaperone

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: chaperone-report
          path: chaperone.html
```

The SARIF output is shaped for code scanning. File paths are relative to
the enclosing git repository (`uriBaseId: SRCROOT`), so alerts land on
the right files and the report never contains your local directory
layout. Each result carries a stable `partialFingerprints` entry, so an
alert keeps its identity across runs. Each rule has a
`security-severity`, so the Critical/High/Medium/Low label shows in the
Security tab. Every check that ran is listed as a rule, so fixing a
finding closes its alert.

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

Chaperone runs 37 checks across six categories — secrets & credential
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
   `DECISIONS.md`, Phase 20. `chaperone check-update` is the one
   command that makes a real outbound network call to the internet (the
   npm registry) — entirely separate from `scan`, opt-in only, and
   never run automatically by anything.
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

**Reporter output is golden-file/snapshot tested**
(`test/scan/reporterSnapshots.test.ts`, improvement_plan.md 5.1) against
both fixtures, across every format — catches an accidental whitespace/
ordering/field regression a substring assertion could miss. A deliberate
output change (adding a field, rewording a line) means updating the
snapshot: `npx vitest run test/scan/reporterSnapshots.test.ts -u`, then
review the diff in `test/scan/__snapshots__/` like any other source
change before committing it.

**The config parser and the `.gitignore` matcher are property-based
fuzz tested** (`test/discovery/configParser.fuzz.test.ts`,
`test/checks/shared/gitignoreMatch.fuzz.test.ts`, using
[fast-check](https://github.com/dubzzz/fast-check),
improvement_plan.md 5.2) against hundreds of generated inputs per run,
beyond the hand-picked cases the rest of the test suite covers —
exactly the "small, pure, input-shape-sensitive function" category the
plan calls out. This already caught two real bugs during development
(an uncaught exception from the underlying `ignore` package on a
handful of edge-case path strings, and a flawed test assumption about
`-0`'s JSON round-trip) — see `DECISIONS.md`, Phase 23 (5.2).

**A performance/scale test** (`test/scan/performance.test.ts`,
improvement_plan.md 5.3) generates a synthetic 500-skill install at test
time and asserts discovery + the full check suite completes within a
generous wall-clock ceiling — not a micro-benchmark, but a concrete
floor that would fail loudly on a real algorithmic regression (e.g. an
accidental O(n²) in discovery or the check engine) rather than only
being discovered as a real user complaint. A real run currently
completes in well under a second.

**Mutation testing** (`npm run mutation`, [Stryker](https://stryker-mutator.io/),
improvement_plan.md 5.4) is a non-blocking, "tests for the test suite"
CI signal — verifies the existing coverage would actually catch a
regression, not just that it currently passes. Deliberately scoped to a
small, fast subset (`configParser.ts`/`gitignoreMatch.ts` — the same two
modules 5.2 already fuzz-tests) rather than the whole `src/` tree, which
would be too slow to run on every push; runs in `mutation-testing`, a
separate CI job that is not a required status check, so it can never
block a merge. `stryker.config.mjs`'s own `thresholds.break` is also
`null` — the mutation score itself never fails the `stryker run`
process either. See `DECISIONS.md`, Phase 23 (5.4) for the full scoping
rationale, including a real worker-thread/`process.chdir()` constraint
this had to be designed around.

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
