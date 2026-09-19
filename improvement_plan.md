# Chaperone — Improvement Plan

A working backlog of weak points and opportunities, written after shipping
v1 (22 checks, 3 reporters, published as `@alpay_altuntas/chaperone` on
npm) and then revisited with a closer, line-by-line pass over every
discovery module and check. This is analysis only — nothing here is
implemented yet. Each item gets an **Impact** and **Effort** tag
(Low/Med/High); see [Suggested roadmap](#suggested-roadmap) at the end.

Current shape of the codebase, for reference: 2,848 lines in `src/`, 39
test files, 22 checks across 6 categories, 4 runtime dependencies
(`commander`, `picocolors`, `yaml`, `zod`).

**Revision note:** the first pass at this document was too shallow — it
stayed at the architecture level (regex-vs-AST, no real config schema)
without actually re-reading every module for concrete bugs. This revision
adds ~25 new items found that way: real false-positive/false-negative
bugs in shipped checks, a gap against the *original spec's own stated
scope* (persistent memory/state, §2, is never discovered or checked at
all), nine new concrete check candidates, and a full pass over reporters,
CLI, and test/process gaps that weren't covered before.

---

## Part 1 — Correctness bugs & weak points in what's shipped

Ordered roughly by how directly they cause a wrong (false-positive or
false-negative) finding today, not just a theoretical gap.

### 1.1 Capability detection is regex-only, not AST-based

**Impact: High. Effort: High.**

`src/discovery/skillsScanner.ts` detects shell/fs/network capabilities and
destructive keywords entirely via regex over raw source text (e.g.
`/\bexecSync?\(/`, `/\bfetch\(/`). This is the foundation almost every
agency/injection check (`CHAP-AGY-001..004`, `CHAP-INJ-002`) is built on,
and it has real, known failure modes:

- **False negatives**: dynamic access (`child_process['exec']`), string
  concatenation to build a function name, re-exported/aliased imports,
  anything behind a thin wrapper function.
- **False positives**: the pattern appearing in a comment or string
  literal.
- **The word-boundary bug we already found and worked around**: `\bdelete\b`
  doesn't match `deleteFile` (no non-word boundary between `e` and `F`).
  The `file-writer`/`messenger` fixtures had to reference the words in
  *comments* to get real test coverage — a tell that the underlying
  heuristic is fragile, not just the fixture.

A real fix means parsing skill source into an AST (TypeScript's own
compiler API, or a lighter parser like `acorn`/`meriyah` for plain JS) and
matching call expressions / identifier bindings instead of text patterns.
Highest-leverage accuracy improvement available — nearly everything in
the "agency" and "injection" categories inherits this layer's confidence.

### 1.2 `SECRET_KEY_PATTERN` misses almost every `*_key` name that isn't literally `api_key`

**Impact: High. Effort: Low.** *(New finding from this pass.)*

`src/discovery/configParser.ts:5`:

```ts
const SECRET_KEY_PATTERN = /(api[_-]?key|token|secret|password|passwd|credential)/i;
```

The `key` branch only matches the literal sequence `api` immediately
before `key` (`api_key`, `api-key`, `apikey`). A config field named
`private_key`, `ssh_key`, `encryption_key`, `signing_key`,
`master_key`, or just `key` — every one of which is a completely
ordinary, common name for a real secret — **is invisible to
`CHAP-SEC-001`/`CHAP-SEC-002`/`CHAP-SEC-004` entirely**: not masked, not
flagged, not counted as a literal secret for any downstream check. This
is a direct false-negative in the tool's single most important check.
Fix is small (broaden to a word-boundary-aware generic `key` match,
e.g. `\bkey\b` alongside the existing terms, careful not to false-positive
on words like "keyboard"/"keyword" — `\bkey\b` alone already avoids
those) but the impact is large given how central this check is.

### 1.3 `CHAP-NET-001` false-positives on valid loopback addresses outside the one literal it checks

**Impact: Med. Effort: Low.** *(New finding from this pass.)*

`src/checks/network/chapNet001GatewayExposed.ts:7`:

```ts
const LOCALHOST_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);
```

All of `127.0.0.0/8` is loopback-only in IPv4 — `127.0.0.2`, `127.1.2.3`,
etc. are exactly as safe as `127.0.0.1`, but any of them would be
**incorrectly flagged as "exposed"** since only the single literal
`127.0.0.1` is in the set. Same problem for IPv6 loopback written in
long form (`0:0:0:0:0:0:0:1` or `0000:0000:...:0001`) instead of the
short `::1`. A real (if slightly unusual, but valid) gateway config using
either form gets a false-positive critical finding. Fix: parse the
address and check "is this in `127.0.0.0/8`" / "is this the IPv6 loopback
after normalization" rather than a literal string-equality set.

### 1.4 `~` (home-directory) paths in config are silently resolved wrong

**Impact: Med. Effort: Low.** *(New finding from this pass.)*

`src/discovery/logging.ts:24-25`:

```ts
const rawPath = typeof logging['path'] === 'string' ? logging['path'] : null;
const resolvedPath = rawPath !== null ? path.resolve(targetRoot, rawPath) : null;
```

`path.resolve` has no concept of `~` — it's a shell convention, not a
filesystem one. A config with `logging: { path: ~/logs/agent.log }`
(common; some config-loading libraries do expand `~` themselves even
outside a shell) resolves to `<targetRoot>/~/logs/agent.log`, treating
the literal three characters `~` as a subdirectory name. The real log
file then silently doesn't exist at the path Chaperone thinks it's at —
`CHAP-SEC-003`'s and `CHAP-SEC-004`'s permission checks on the log file
quietly check nothing, with no error surfaced (the permission fact just
comes back `exists: false`, indistinguishable from "no log file
configured"). Fix: expand a leading `~/` or bare `~` to `os.homedir()`
before resolving, same as `configLocator.ts` already does for the default
install-root list.

### 1.5 Env-reference detection doesn't recognize default-value syntax (`${VAR:-default}`)

**Impact: Med. Effort: Low.** *(New finding from this pass.)*

`src/discovery/configParser.ts:9`:

```ts
const ENV_REF_PATTERNS = [/^\$\{[A-Za-z0-9_]+\}$/, /^env:[A-Za-z0-9_]+$/i, /^\$[A-Za-z0-9_]+$/];
```

Only bare `${VAR}` is recognized. Bash/docker-compose-style parameter
expansion with a default or error fallback — `${VAR:-default}`,
`${VAR:=default}`, `${VAR:?error message}` — is extremely common in real
configs and templating, and **doesn't match** any of these three
patterns. A config using that (very ordinary, very safe) style gets its
value treated as a literal secret: masked and flagged as a
`CHAP-SEC-001`/`CHAP-SEC-002` finding, a false positive. Fix: extend the
first pattern to allow an optional `[:-=?][^}]*` suffix before the
closing brace.

### 1.6 `.env` / sidecar secret files are completely outside discovery's field of view

**Impact: High. Effort: Med.** *(New finding from this pass.)*

Extremely common real-world pattern: `config.yaml` references
`${API_KEY}`, and a colocated `.env` file (or `secrets.yaml`,
`credentials.json`, etc.) actually holds the literal value, loaded by the
agent's own startup process. Chaperone currently has **zero visibility**
into any such file — `configLocator.ts` only ever looks for
`config.{yaml,yml,json}`, and nothing else in discovery scans the target
root for other credential-bearing files. That means the single most
common place a real literal secret would actually live is invisible to
every secrets check (`CHAP-SEC-001..004`) — the exact scenario those
checks exist for. Concrete fix: have discovery look for a short list of
conventional sidecar files (`.env`, `.env.local`, `secrets.yaml`,
`secrets.json`) alongside the main config, and feed them through the same
masking/permission/git-tracking pipeline the main config already gets.
See also [2.9](#29-new-check-candidates) below for the specific new
checks this unlocks.

### 1.7 No discovery of persistent memory/state at all — a gap against the *original spec's own scope*

**Impact: High. Effort: Med.** *(New finding from this pass.)*

`instruction.md` §2 lists exactly five artifacts Chaperone's job is to
discover: config file, skills directory, gateway daemon, **"Persistent
memory / state stored on disk,"** and logs. Four of five have discovery
modules and checks. The fifth — memory/state — has **none**: no
`discovery/memory.ts`, no `AgentModel` field, no `CHAP-*` check
references it anywhere. This isn't a "nice to have" feature idea; it's
scope explicitly called for in the spec that was never built. A
conversation-memory/state store is exactly the kind of thing that
accumulates sensitive content over time (user messages, tool outputs,
sometimes even secrets that passed through a conversation) and deserves
the same permission/git-tracking scrutiny `config.yaml` gets. Concrete
shape: a `memory_dir`/`state_dir`-style config field (mirroring
`skills_dir`'s existing pattern) pointing at a directory; new checks for
"memory store is group/other readable" and "memory store is
git-tracked/not gitignored," directly parallel to `CHAP-SEC-002/003`.

### 1.8 Logging checks only ever look at *configuration*, never at what's already *in* existing log files

**Impact: Med. Effort: Med.** *(New finding from this pass.)*

`CHAP-SEC-004`/`CHAP-OBS-002` both reason about whether logging is
*configured* in a way that's likely to leak secrets going forward. Chaperone
never actually opens an existing log file and checks whether a secret
*already* leaked into it from a past run (common in practice: someone
temporarily sets `level: debug` to chase a bug, a request containing an
API key gets logged, then the level gets turned back down — the leaked
value sits in the log file indefinitely). A bounded scan of existing log
content (reusing `SECRET_KEY_PATTERN`-style matching, or a generic
high-entropy-string heuristic, capped at a sane byte limit) for
already-present secret-shaped strings would catch a real, distinct risk
that the current forward-looking checks structurally cannot.

### 1.9 Skill scanning is Node/TS-only — non-JS skills are entirely invisible

**Impact: High (strategic, ties to §2.1). Effort: High.**

`SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts'])`
(`skillsScanner.ts:9`). Every capability/destructive-keyword/dangerous-install
heuristic is JS-pattern-specific (`execSync`, `fetch`, `require(...)`). A
skill written in Python (`subprocess.run`, `os.system`), a shell script,
or any other language is **completely invisible** — not flagged, not
even counted as "inspected," just silently absent from the model as if
it doesn't exist. Given how much of the real self-hosted-agent ecosystem
is Python (this was already implicitly assumed away in `DECISIONS.md`'s
"the target agent ecosystem is Node/TS" rationale, which was an
assumption about the *fictional* Clawdbot format, not a validated fact
about real agents), this is a major blind spot for real-world use. Ties
directly into [2.1](#21-target-at-least-one-real-agent-framework) — any
real framework adapter needs at minimum a Python capability-detection
pass (even a regex-based first cut: `subprocess`, `os.system`, `eval`,
`requests.get`, etc. — same fragility as 1.1, but better than nothing).

### 1.10 No size/complexity guard before parsing the main config or any skill manifest/lockfile

**Impact: Low (self-DoS hardening). Effort: Low.** *(New finding from this pass.)*

Skill *source* files get a `MAX_SOURCE_FILE_BYTES` (256 KB) guard before
reading (`skillsScanner.ts`), but the **main `config.yaml`/`.json`**
(`discovery/index.ts`), every skill's `package.json`/lockfile, and
`.gitignore` are all read and parsed with no size limit at all. A
pathological (accidentally huge, or adversarially crafted) config file —
or a YAML file exploiting anchor/alias expansion to blow up in memory
disproportionate to its file size (a "billion laughs"-style amplification
the `yaml` package doesn't fully guard against on its own) — could cause
excessive memory/CPU use during a scan. Low real-world likelihood (this
is the user's own config), but a security tool scanning
potentially-attacker-influenced content (a skill installed from an
unverified source, per `CHAP-SUP-001`, could ship a hostile
`package.json`) should guard its own resource usage the same way it
already does for skill source.

### 1.11 Untrusted skill metadata (name/author) is interpolated into console output with no sanitization

**Impact: Low. Effort: Low.** *(New finding from this pass.)*

`skill.name` and `skill.provenance.author` come straight from a skill's
own manifest — by definition untrusted content once `CHAP-SUP-001`
("unverified source") exists as a category at all. These values get
directly string-interpolated into finding messages and printed via
`console.log` in the console reporter with no control-character
stripping. A malicious skill manifest with a `name` field containing ANSI
terminal escape sequences could manipulate the user's terminal (clear
the screen, hide subsequent output, etc. — a known "terminal injection"
class of issue for any tool that prints untrusted strings). The
JSON/SARIF reporters are unaffected (`JSON.stringify` escapes control
characters correctly) — this is console-reporter-specific. Fix: strip/escape
non-printable and ANSI-escape control characters from any
manifest-derived string before it reaches `formatConsoleReport`.

### 1.12 No distinction between "Chaperone found real issues" and "Chaperone itself errored" in the exit code

**Impact: Med. Effort: Low.** *(New finding from this pass.)*

`runChecks` already isolates a single broken *check* (catches the
exception, emits an `info`-severity finding instead of crashing). But an
unexpected error in a *reporter* (e.g. `renderReport` throwing on some
edge-case input) is not caught anywhere in `cli.ts` — it would surface as
a raw Node stack trace and Node's default uncaught-exception exit code
`1`. That's **indistinguishable from "findings met `--fail-on`"** to a
CI pipeline reading only the exit code. A top-level try/catch around the
whole `scan` action, mapping any unexpected error to a distinct exit code
(e.g. `2`, "tool error" vs. `1` "findings exceeded threshold") with a
clean one-line message, closes this — same pattern already used for the
`--output` write-failure case, just not applied universally yet.

### 1.13 `CHAP-SEC-002`'s git-context signal doesn't check global excludes or actual tracked status

**Impact: Low. Effort: Med.**

`gitContext.ts` only reads the repo-root `.gitignore`. Real git also
honors `.git/info/exclude` (a per-clone, never-committed exclude file)
and a user's `core.excludesFile` (a global gitignore outside any repo).
A file excluded via either mechanism would be a false positive for
`CHAP-SEC-002` today. Separately, "not gitignored" isn't the same as
"actually tracked" — a file could be merely *untracked and unignored*
(one `git add` away from being committed, but not yet in history), which
is arguably lower-severity than a file that's actually been committed.
Distinguishing the two would need shelling out to `git` (`git
check-ignore`, `git ls-files`) — new I/O surface (currently discovery
never invokes an external process, only reads the filesystem directly),
a real trade-off worth deciding deliberately rather than by omission.

### 1.14 `.gitignore` matching covers a small subset of real semantics

**Impact: Low. Effort: Med.**

`src/checks/shared/gitignoreMatch.ts` (backing `CHAP-SEC-002`) explicitly
doesn't support `**` or nested (non-root) `.gitignore` files. Worth
revisiting with a small, well-tested library (`ignore` on npm is the de
facto standard, ~500 bytes gzipped) rather than hand-rolling more glob
semantics — trading "minimal dependencies" for "correct behavior" on a
security-relevant check seems like the right call here.

### 1.15 `CHAP-SUP-003` is close to useless as a signal

**Impact: Med. Effort: High (real fix) / Low (mitigation).**

Already a documented v1 limitation. It fires on *any* skill with a
`package.json`, dragging down the posture score uniformly regardless of
actual risk (`test/scan/fullCatalog.test.ts`: the hardened `clean-agent`
fixture scores 55/D purely from this). Mitigation: demote to `info`
severity so it stops affecting `--fail-on high`/the score while staying
visible. Real fix: a periodically-updated **offline** vulnerability
database (OSV/npm-audit snapshot, refreshed out-of-band, never fetched
live during a scan — preserving the no-network guardrail), per the
original spec's own §16 stretch goal.

### 1.16 `CHAP-INJ-002` is a shape-match, not a data-flow trace

**Impact: Med. Effort: High.**

Flags any skill with *both* shell-exec and network/fs capability in the
same file, regardless of whether one actually feeds the other. Meaningfully
improving this needs the same AST work as 1.1, plus real variable
data-flow tracking — a genuine static-analysis project, not a quick patch.

### 1.17 No line numbers in any finding, ever

**Impact: Low. Effort: Med.**

Every `Finding.location.line` is `null`. The `yaml` package (already a
dependency) supports CST/document parsing with source ranges
(`YAML.parseDocument`); wiring that through the masking pass would let
`CHAP-SEC-001`-style findings point at an exact line for YAML configs.

### 1.18 File-permission checks are POSIX-only, silently

**Impact: Low. Effort: Low (docs/skip) / Med (real support).**

`CHAP-SEC-003` and `CHAP-SEC-004`'s permission branch are meaningless on
Windows — noted inline in `permissions.ts` but not surfaced to a user
before they run a scan there. At minimum, detect the platform and report
these two as explicitly skipped-with-reason on Windows rather than
silently reporting a mode value that doesn't mean what it looks like.

### 1.19 Symlinked shared code inside a skill is invisible to the source scanner

**Impact: Low. Effort: Low.**

`listSourceFiles`'s recursion checks `entry.isDirectory()`, which is
`false` for a symlink even when it points at a directory — so (mostly by
accident) we're safe from symlink-loop infinite recursion, but a skill
that legitimately shares code via a symlinked directory has that code
silently unscanned. Worth an explicit, bounded `realpathSync` + visited-set
check if this turns out to matter in practice (low priority — mostly
noting the current behavior is accidental, not designed).

### 1.20 Config discovery only checks one location for the main config file

**Impact: Low. Effort: Low.**

`configLocator.ts`'s `CONFIG_FILENAMES` are only ever checked directly
under the target root — no `config/config.yaml`, `.chaperone/config.yaml`,
or similar nested convention some real tools use. Minor given explicit
`chaperone scan <path>` is already documented as the reliable interface,
but worth a short list of one-level-nested fallbacks.

---

## Part 2 — New check candidates

Concrete, specific enough to implement directly (each would need its own
fixture pair, same as every existing check) — this is the most
directly-product-shaped part of this plan, since the check catalog *is*
the product.

### 2.1 `CHAP-SEC-005` — Secret already present in existing log content

Scans existing log file content (bounded, e.g. last N KB or M lines) for
secret-shaped strings, reusing the broadened `SECRET_KEY_PATTERN`-style
matching or a generic high-entropy-string heuristic. Distinct from
`CHAP-SEC-004`, which only reasons about whether logging *will* leak
going forward. See [1.8](#18-logging-checks-only-ever-look-at-configuration-never-at-what-is-already-in-existing-log-files).

### 2.2 `CHAP-SEC-006` — Sidecar secret file (`.env` etc.) exposed

Once discovery finds `.env`/`secrets.yaml`/`secrets.json` (see
[1.6](#16-env--sidecar-secret-files-are-completely-outside-discoverys-field-of-view)),
apply the same permission (`CHAP-SEC-003`-style) and git-tracking
(`CHAP-SEC-002`-style) checks to it that the main config already gets.

### 2.3 `CHAP-SEC-007` — Config references an environment variable that isn't actually set

At scan time, check whether a `${VAR}`-style reference in config
resolves to anything in `process.env`. Necessarily best-effort/advisory
(Chaperone runs as a separate process from the agent and may not share
its environment, e.g. if the agent is launched via `systemd`/`launchd`
with its own `EnvironmentFile`) — should be clearly labeled low-confidence
in its message, but still a real, currently-invisible failure mode
("looks safe, but is actually broken/empty at runtime").

### 2.4 `CHAP-NET-004` — Overly permissive CORS on the gateway

If gateway config exposes a CORS setting (`Access-Control-Allow-Origin:
*` or equivalent), flag it — a real exposure vector for browser-based
attacks against a gateway that's correctly bound to localhost but still
reachable from any web page open in a local browser.

### 2.5 `CHAP-NET-005` — No rate limiting on the gateway control API

Absence of any rate-limit/backoff config on the gateway is a
brute-force/DoS exposure, particularly relevant given `CHAP-NET-002`
already flags weak auth tokens — the two compound.

### 2.6 `CHAP-SUP-005` — Obfuscated or dynamically-evaluated code in a skill

Detect `eval(`, `new Function(`, `atob(...)` immediately followed by
`eval`, or similar decode-then-execute chains in skill source. A strong
backdoor/malware smell independent of what's actually being hidden —
this exact pattern is a hallmark of real supply-chain attacks in the npm
ecosystem (obfuscated payloads in otherwise-innocuous-looking packages).

### 2.7 `CHAP-SUP-006` — Typosquat-risk dependency name

Flag a skill dependency whose name is suspiciously close (small edit
distance) to a well-known popular package name — a small bundled
reference list would be enough for a useful first cut, no live lookup
needed (preserves the no-network guardrail).

### 2.8 `CHAP-OBS-004` — Persistent memory/state store exposed

Directly fills the [1.7](#17-no-discovery-of-persistent-memorystate-at-all--a-gap-against-the-original-specs-own-scope)
gap: once a memory/state directory is discoverable, flag it if
group/other-readable or git-tracked-and-not-ignored, mirroring
`CHAP-SEC-002`/`CHAP-SEC-003`'s existing logic.

### 2.9 `CHAP-INJ-005` — Inbound channels don't distinguish trust level

`CHAP-INJ-003` today checks for a single, global `trust.tool_allowlist`.
It doesn't check whether *different* channels should carry *different*
trust levels — e.g. a public Discord server the agent listens on vs. a
private, admin-only Telegram chat, currently treated identically once
any allowlist exists at all. A per-channel (not just global) allowlist
convention, and a check that flags a broad allowlist applied uniformly
across a mix of public and private channels, would catch a real and
fairly common misconfiguration shape.

---

## Part 3 — Strategic & feature opportunities

### 3.1 Target at least one real agent framework

**Impact: High. Effort: Med–High.**

The single highest-value move available, and the fix for both
[1.9](#19-skill-scanning-is-nodets-only--non-js-skills-are-entirely-invisible)
and the broader "targets a fictional format" limitation. Rather than (or
in addition to) the invented Clawdbot-style format, add a discovery
**adapter** for a real, popular self-hosted agent pattern:

- **MCP (Model Context Protocol) server configs** — increasingly the
  standard way personal AI assistants wire up tools/skills; real, growing,
  well-specified.
- **Open Interpreter** — a real, popular self-hosted agent with local
  shell/file access and an actual config format to target.
- A **generic adapter interface** instead of one fixed target: keep
  `AgentModel` as the stable core, make the config-locate/parse/skill-scan
  layer swappable per "profile" (`chaperone scan --profile mcp
  ~/.config/claude`). Cleanly solves the fictional-format problem without
  discarding the existing fixture-based test suite — the current format
  just becomes one profile among several.

### 3.2 Multi-root / batch scanning

**Impact: Med. Effort: Med.** *(Missing from the first pass.)*

`chaperone scan --all ~/agents/*` or a small workspace-config file
listing several agent installs, producing one aggregate report (or N
separate ones) in a single CI run — relevant for anyone managing more
than one bot/assistant. Natural extension once discovery/engine already
cleanly separate "one install → one model → findings."

### 3.3 Docker/container-aware scanning

**Impact: Med. Effort: Med–High.** *(Missing from the first pass.)*

Many real self-hosted agents run inside a container. `chaperone scan
--docker <container>` (inspecting a mounted volume or `docker exec`-ing a
read-only listing) would meet users where they actually deploy. Also
surfaces a subtlety worth designing around deliberately: containerized
env-var injection (via `docker-compose.yml` `environment:`/`env_file:`)
means the *literal secret* is often one layer removed from both the
agent's config *and* Chaperone's own process environment — 
[2.3](#23-chap-sec-007--config-references-an-environment-variable-that-isnt-actually-set)'s
env-var-resolution check would need to account for this (e.g. optionally
reading a referenced `docker-compose.yml`'s `env_file:`).

### 3.4 Per-project configuration file (`.chaperonerc.json`)

**Impact: High. Effort: Med.**

No way today to override a check's severity or suppress a specific,
consciously-accepted finding — an explicit §16 stretch goal. Proposed
shape:

```jsonc
{
  "severityOverrides": { "CHAP-SUP-003": "info" },
  "ignore": [
    { "checkId": "CHAP-NET-001", "reason": "intentional — behind a VPN-only interface", "expires": "2026-12-31" }
  ],
  "disabledChecks": ["CHAP-OBS-003"]
}
```

An `expires` field on suppressions (borrowed from real-world security-linter
configs) avoids a suppression silently outliving its reason — Chaperone
could warn (not fail) on an expired one, prompting re-review. Score
weights (`SEVERITY_SCORE_WEIGHT` in `engine/severity.ts`) should be
overridable here too, not just check severities.

### 3.5 Baseline / diff mode for CI

**Impact: High. Effort: Med.**

`chaperone scan ~/clawd --baseline last-scan.json` reports only *new*
findings vs. a prior run — the standard shape for adopting a linter on an
existing, imperfect codebase without either fixing everything on day one
or disabling `--fail-on` entirely. A baseline file is just a saved JSON
report; the schema already supports this for free.

### 3.6 `npm provenance` + a real release workflow

**Impact: Med. Effort: Low.**

Directly motivated by how painful the manual publish was (2FA, token
creation, a scope-name bug only caught at the real registry — see
`DECISIONS.md`). GitHub Actions OIDC "trusted publishing" removes the
token/2FA friction for future releases entirely; `npm publish
--provenance` cryptographically ties the package to the exact build that
produced it — a meaningful trust signal for a *security* tool, and nearly
free once CI-based publishing exists.

### 3.7 `chaperone explain <check-id>`

**Impact: Low. Effort: Low.**

`chaperone checks` only gives id/title/severity; full detail only lives
in `CHECKS.md`. Pairs naturally with
[4.2](#42-generate-checksmd-from-the-check-registry-instead-of-hand-maintaining-it)
below so the two data sources can't drift apart.

### 3.8 Category- and severity-level display filtering

**Impact: Low. Effort: Low.**

`--only-category secrets,network` / `--skip-category observability`
(more ergonomic than listing every ID by hand), and `--min-severity
medium` as a *display* filter distinct from `--fail-on` (which only
controls the exit code).

### 3.9 Additional reporters: Markdown and GitHub Actions annotations

**Impact: Med. Effort: Low–Med.** *(Markdown reporter missing from the first pass.)*

- **`--format markdown`**: a PR-comment-ready table — cheaper to build
  than the HTML reporter, and directly useful for the CI use case already
  documented in the README (post as a PR comment via `gh pr comment`).
- **GitHub Actions "problem matcher" / `::warning file=...::` annotation
  output**: inline PR annotations without the full SARIF code-scanning
  upload flow — GitHub-native, complements SARIF rather than replacing it.

### 3.10 HTML reporter

**Impact: Low. Effort: Med.**

Explicit §16 stretch goal. A single self-contained HTML file, no external
JS/CSS dependency — friendlier than JSON for a non-technical stakeholder,
richer than plain console text pasted into a doc.

### 3.11 Console reporter: `--quiet`/`--summary-only` modes

**Impact: Low. Effort: Low.** *(Missing from the first pass.)*

`--summary-only` prints just the summary line + score, no per-finding
detail — a quick health-check use case. `--quiet` prints one line per
finding (id + severity only) instead of the full four-line block — useful
for high-volume CI logs where the full JSON/SARIF report is the real
artifact and console output is just a glance.

### 3.12 Environment-variable support for common CLI flags

**Impact: Low. Effort: Low.** *(Missing from the first pass.)*

`CHAPERONE_FAIL_ON=high`, `CHAPERONE_FORMAT=json`, etc. — many CI systems
prefer environment-based configuration over CLI flags for shared/reusable
job definitions. Commander supports this cheaply via option defaults
sourced from `process.env`.

### 3.13 Plugin system for custom/organization-specific checks

**Impact: Med. Effort: High.**

The `Check` interface (`src/engine/types.ts`) is already a small, clean
contract (`{ id, title, severity, category, owasp, run(model) }`) — the
work is a loading mechanism (`--plugin ./my-checks.js` or a config-file
array of check modules). Worth an explicit design note: a plugin *is*
arbitrary code with full access to `AgentModel`, no sandboxing — exactly
the kind of thing a reviewer of a *security* tool would ask about
immediately, so this should be documented as an explicit trust boundary
("loading a plugin means trusting it fully") rather than left implicit.

### 3.14 Guided remediation (`chaperone fix`, deliberately scoped)

**Impact: Med. Effort: High.**

Explicitly out of scope for v1 (§3), correctly. If ever built, it must be
a **separate, explicit, opt-in command that never runs during `scan`**,
preserving the read-only guardrail (§14) for the scanner itself — e.g.
`chaperone fix CHAP-SEC-001 --dry-run` prints a diff, nothing is written
unless the user re-runs with `--write` after reviewing it. A materially
different trust posture from the scanner and should be named/packaged
distinctly enough that "Chaperone found this" and "Chaperone changed
this" are never confusable.

### 3.15 Opt-in, explicit update check (careful framing)

**Impact: Low. Effort: Low.** *(Missing from the first pass — floated cautiously.)*

`chaperone --check-update` as a separate, manually-invoked command (never
run implicitly during `scan`, never on by default) could nudge users
toward a newer version, the way many CLIs do. Flagged as "maybe,
carefully" rather than a firm recommendation: it's in some tension with
the project's own no-network-by-default, privacy-conscious framing, and
should probably require an explicit opt-in flag or config setting rather
than shipping enabled.

---

## Part 4 — Process & repo hygiene gaps

### 4.1 No `CHANGELOG.md`

**Impact: Med (now that we're actually publishing). Effort: Low.**

Recommend [Keep a Changelog](https://keepachangelog.com) format, plus a
documented policy: **a new check landing, or a check's severity
changing, is a semver-minor bump at minimum** (it can change exit-code
behavior for existing CI setups), even before 1.0.0.

### 4.2 Generate `CHECKS.md` from the check registry instead of hand-maintaining it

**Impact: Med. Effort: Med.** *(Missing from the first pass.)*

Every check module already carries id/title/severity/category/owasp as
exported constants. `CHECKS.md` is currently hand-written and
hand-synced — a real drift risk as checks are added/changed (already
relies on remembering to update it, as every phase's commit messages
attest). A small script (`npm run docs:checks`) that regenerates the
catalog table from the actual `ALL_CHECKS` registry (plus a
free-text "detects"/"heuristic" doc-comment per check, extracted or kept
alongside) would make the two impossible to desync, and is what
[3.7](#37-chaperone-explain-check-id)'s `explain` subcommand should
read from too.

### 4.3 No `SECURITY.md`

**Impact: Med. Effort: Low.**

For a *security tool*, no documented vulnerability-disclosure path is a
notable gap — both for bugs in Chaperone itself, and for the subtler
case of "this check produces a false negative that matters" (arguably a
security-relevant report in its own right for a scanner). Should state:
where to report, expected response time, and that both classes of issue
are in scope.

### 4.4 Automate the packaged-binary smoke test in CI

**Impact: Med. Effort: Low.** *(Missing from the first pass, but referenced by DECISIONS.md.)*

The `npm pack` → install into a scratch dir → run the installed binary
check that caught the real symlink-entrypoint bug is currently a manual
step documented in the README's contributing notes. It should run in CI
on every push (not just before a publish) — it's cheap, and it's the
*only* check in the whole pipeline that would have caught that bug before
it reached a real user.

### 4.5 No coverage reporting

**Impact: Low. Effort: Low.**

`vitest` supports coverage out of the box (`@vitest/coverage-v8`). Given
how much of this project's trust story rests on "every check has
explicit TP/TN coverage," a coverage badge alongside the CI badge would
make that credible at a glance instead of only asserted in prose.

### 4.6 Chaperone doesn't audit its own dependencies

**Impact: Low. Effort: Low.**

No Dependabot config, no `npm audit`/`npm audit signatures` step in CI
for Chaperone's own dependencies. Slightly ironic for a security scanner;
cheap to close.

### 4.7 No issue/PR templates

**Impact: Low. Effort: Low.**

A bug-report template prompting for "which check," "expected vs. actual
finding," and "redacted config snippet if possible" would get far more
useful reports than a blank box, especially given how much of this
tool's behavior is heuristic (see Part 1) and genuinely benefits from
real-world counterexamples.

### 4.8 No documented positioning vs. adjacent tools

**Impact: Low. Effort: Low.** *(Missing from the first pass.)*

Generic secret scanners (gitleaks, trufflehog) and dependency scanners
(`npm audit`, Snyk) already exist and do parts of what
`CHAP-SEC-*`/`CHAP-SUP-*` do, generically. Worth a short README/docs
section clarifying that Chaperone's actual differentiator is the
agent-specific categories no generic tool covers at all — excessive
agency (`CHAP-AGY-*`), prompt-injection surface (`CHAP-INJ-*`), and
gateway/observability posture (`CHAP-NET-*`/`CHAP-OBS-*`) — rather than
competing head-on for secrets/dependency detection, and that it's meant
to complement those tools, not replace them.

---

## Part 5 — Testing & QA process gaps

*(New section — not present in the first pass.)*

### 5.1 No golden-file/snapshot testing of full reporter output

**Impact: Low. Effort: Low.**

Current reporter tests assert specific substrings/counts, not full
output. A snapshot test of the complete console/JSON/SARIF output against
both fixtures would catch unintended formatting regressions (e.g. an
accidental whitespace/ordering change) that substring assertions can
miss entirely.

### 5.2 No fuzz/property-based testing of the parsers

**Impact: Low. Effort: Med.**

The config parser and the hand-rolled `.gitignore` matcher
(`checks/shared/gitignoreMatch.ts`) are exactly the kind of small, pure,
input-shape-sensitive functions that benefit most from property-based
testing (`fast-check` is the standard TS library) against malformed or
adversarial input, beyond the specific hand-picked cases in the current
test suite.

### 5.3 No performance/scale testing

**Impact: Low. Effort: Low.**

No test exercises discovery against a large synthetic install (e.g. 500
skills, deep source trees) to establish how scan time scales. Not urgent
at today's usage, but worth having *before* it becomes a real complaint
rather than after.

### 5.4 No mutation testing

**Impact: Low. Effort: Med.**

A "tests for the test suite" concern (e.g. Stryker) — verifies the
existing TP/TN coverage would actually catch a regression, not just that
it currently passes. Probably lower priority than everything else in
this document, but worth a mention given how much this project's trust
story leans on "every check is tested."

---

## Suggested roadmap

Roughly ordered by impact-per-effort, not strict sequencing — several run
in parallel:

1. **Immediate correctness fixes (low effort, high value, no design
   work needed)**: 1.2 (`*_key` pattern), 1.3 (loopback range), 1.4 (`~`
   expansion), 1.5 (`${VAR:-default}`), 1.12 (distinct error exit code),
   1.11 (sanitize untrusted strings before console output).
2. **Quick process wins**: 3.6 (provenance + release workflow — directly
   prevents a repeat of the publish pain), 4.1, 4.3, 4.4 (automate the
   exact check that caught our real bug), 4.5, 4.6, 4.7, 4.2.
3. **Close the biggest spec gap**: 1.6 (`.env`/sidecar files) and 1.7
   (persistent memory/state) — both directly expand what the existing
   secrets-hygiene checks *see*, without needing new architecture, and
   1.7 specifically closes a gap against the original spec's own stated
   scope. Ship alongside 2.1/2.2/2.8, the checks these unlock.
4. **Trust & accuracy (medium-high effort, raises the floor)**: 1.1
   (AST-based capability detection — unblocks 1.16/2.6 too), 1.9
   (non-JS skill detection, at least a first-cut regex pass), 1.14, 1.17,
   1.15's mitigation half (demote `CHAP-SUP-003` to `info` pending the
   real fix).
5. **New checks, once 1.1's AST groundwork exists**: 2.4–2.7, 2.9.
6. **The strategic bet**: 3.1 (real agent framework target/adapter),
   which then resolves 1.9's Python gap for real and makes the
   "fictional format" limitation a solved problem.
7. **Bigger, later**: 3.4 (config/suppression file), 3.5 (baseline/diff
   mode — pairs naturally with real CI adoption once 3.1 exists), 3.2,
   3.3, 3.9, 3.10, 1.15's real-fix half (offline vuln DB), 1.16 (real
   data-flow tracing for `CHAP-INJ-002`), 1.13 (git-tracked-status
   nuance), 5.1–5.4.
8. **Ecosystem, once there's real usage to justify it**: 3.13 (plugin
   system), 3.14 (guided remediation — deliberately last, given the trust
   and scoping questions it raises), 3.15 (update check, if pursued at
   all).
