# Decisions

Running log of non-obvious choices made while building Chaperone, per
`instruction.md` §0 rule 8.

## Phase 0 — Scaffold

- **Language/runtime: TypeScript on Node.js, ESM (`"type": "module"`).**
  Matches the target agent ecosystem (Clawdbot/Moltbot/OpenClaw are
  Node/TS) per `instruction.md` §4. ESM chosen over CJS since it's the
  forward-compatible default for new Node projects and pairs cleanly with
  `NodeNext` module resolution.
- **CLI framework: `commander`.** Widely used, zero-dependency, good
  TypeScript types, matches the "pick one, justify" instruction in §4.
  `yargs` was the alternative; commander's simpler declarative API was
  preferred for a small, readable command surface (`scan`, `checks`,
  `version`).
- **Test runner: `vitest`.** Faster than `jest` for a small ESM/TS project,
  no separate ts-jest/babel transform config needed, Jest-compatible API so
  it stays approachable.
- **TypeScript 5.9.3**, not the newer 7.0.2 (native/Go-based compiler)
  release: `@typescript-eslint` 8.70 declares a peer range of
  `>=4.8.4 <6.1.0` and does not yet support TypeScript 7, so 5.9.3 (latest
  in the supported range) was used instead. Revisit once typescript-eslint
  ships TS7 support. `strict: true` plus `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, and `noImplicitOverride` enabled for
  maximum type safety, appropriate for a security tool per §0 rule 4
  ("clarity over cleverness" — the stricter compiler catches whole classes
  of bugs before they need a human reviewer).
- **ESLint 10 flat config (`eslint.config.js`) with
  `@typescript-eslint`'s `strict-type-checked` ruleset**, plus
  `eslint-config-prettier` to disable formatting-related lint rules
  (formatting is Prettier's job, not ESLint's).
- **`zod`** included now (per §4) even though no schemas are defined until
  Phase 1 (`AgentModel`) — it's a core, load-bearing dependency for the
  whole project (model validation, report schema), not an incidental one.
- **`tsx`** added as a dev-only dependency to run `src/cli.ts` directly
  during development (`npm run dev`) without a manual build step; it is
  not a runtime dependency of the published tool, which runs compiled JS
  from `dist/` via `tsc`.
- **CI: GitHub Actions**, single job running lint, format check, typecheck,
  build, and test on Node 20 (the floor of the `engines` field) on every
  push/PR to `main`.
- **`.npmrc` with `legacy-peer-deps=true`.** Plain `npm install` on this
  dependency graph (vitest 4's optional browser-mode peers in particular)
  hit an npm 10.9.2/arborist crash (`Cannot read properties of null
(reading 'edgesOut')`) unrelated to any real peer conflict. Forcing
  legacy peer-dep resolution avoids the crash; revisit if a newer npm fixes
  it upstream.

## Phase 1 — Discovery + model

- **Config parser: `yaml` (eemeli/yaml).** Actively maintained, zero
  transitive dependencies, handles both `.yaml`/`.yml`; native `JSON.parse`
  handles `.json` directly rather than routing it through the YAML parser.
- **No canonical Clawdbot/Moltbot/OpenClaw config schema exists** (they are
  illustrative example agents per `instruction.md` §1). The config shape
  discovery expects (`llm.api_key`, `channels.*`,
  `gateway.{host,port,auth,tls}`, `logging.{level,path,redact_secrets,audit}`,
  `skills_dir`) and the skill manifest conventions
  (`package.json`/`skill.json` with `repository`, `author`, `version`/`ref`)
  are therefore a documented, invented-but-plausible convention informed by
  real Node-based agent frameworks, not a verified spec. Both fixtures and
  all discovery parsing follow it; a real install with a different shape
  degrades gracefully (config parses to whatever shape it has, unrecognized
  fields are simply absent from the normalized model) rather than crashing.
- **Default install-root probing list** (`~/.clawd`, `~/clawd`,
  `~/.config/clawdbot`, `~/.moltbot`, `~/.config/moltbot`, `~/.openclaw`,
  `~/.config/openclaw`) is similarly an illustrative guess, used only when
  `chaperone scan` is invoked with no path. Explicit `chaperone scan <path>`
  is the primary, reliable interface.
- **Secret masking happens in discovery, not in checks.** `configParser.ts`
  walks the parsed config tree and replaces any literal value under a
  secret-shaped key (`api_key`, `token`, `secret`, `password`, `credential`,
  case-insensitive) with a masked display form (`sk-…wxyz`, or `***` for
  short values), before the value ever reaches the `AgentModel` that checks
  and reporters operate on. Values that already look like an indirect
  reference (`${VAR}`, `$VAR`, `env:VAR`) are left visible since they carry
  no sensitive material. This gives "secrets are masked in all output"
  (§14) as a structural property of the model itself, independent of which
  checks run — defense in depth, not reliant on every check remembering to
  mask.
- **Gateway/logging fact extraction runs on the RAW (pre-mask) parsed
  config, not the masked `AgentModel.config.data`.** An empty or default
  (`"changeme"`, `"admin"`, ...) gateway auth token is exactly the kind of
  literal value the masking pass would otherwise obscure — but only the
  derived boolean (`authTokenIsDefaultOrEmpty`) is ever stored in the
  model; the raw token string itself is discarded after `gateway.ts` reads
  it once inside `discovery/index.ts`.
- **`AgentModel` covers exactly the six buckets instruction.md §8 lists**
  (masked config, skills+capabilities, file-permission facts,
  gateway/network, logging, inspected/skipped) plus `git` context (needed
  for CHAP-SEC-002, called out explicitly in §7/§8) and `Finding`/`Severity`
  types (explicitly documented as living in `model/types.ts` per the
  project-structure comment in §6). Deliberately **not** included yet:
  per-skill `confirmationRequired`/command-or-domain-allowlist fields for
  CHAP-AGY-002/003/004 — those checks aren't implemented until Phase 3, and
  guessing their manifest schema now would be inventing scope ahead of the
  check that consumes it. Extend `Skill`/`GatewayModel` then, once the
  actual heuristic is known.
- **`.gitignore` pattern matching is check logic, not discovery.** Per the
  read boundary in §8 ("even then only read directory existence and
  `.gitignore`, nothing else"), `discovery/gitContext.ts` only detects an
  ancestor `.git` directory and reads the root-level `.gitignore`'s raw
  lines into `GitContext.gitignorePatterns` (I/O). Deciding whether the
  config path matches one of those patterns is pure logic with no I/O, so
  it's deferred to CHAP-SEC-002 in Phase 3 rather than implemented (and
  potentially over-engineered with real gitignore glob semantics) now,
  before any check needs it. Only a repo-root `.gitignore` is read — nested
  `.gitignore` files in intermediate directories are a known, documented
  limitation.
- **File-permission fixtures are set via `chmod` at test time, not via
  committed file mode.** Git only preserves the executable bit; a file
  committed as `0600` can check out as `0644` on another machine/CI runner
  depending on umask. `test/discovery/permissions.test.ts` creates its own
  temp files with explicit modes instead of relying on fixture file
  permissions as checked out from git.
- **`discovery/gateway.ts` and `discovery/logging.ts` are peers**, both
  projecting normalized facts out of the raw parsed config; `logging.ts`
  wasn't in the original §6 skeleton but follows the same pattern as
  `gateway.ts`, which was.
- **Skill capability/install-script detection is static regex/keyword
  matching over source text** (`child_process`/`exec(`/`spawn(` for shell,
  `fetch(`/`http(s).request(` for network, `fs.writeFile`/`unlink`/etc. for
  filesystem, `curl | bash`/`sudo`/`apt-get install`/`brew install` for
  dangerous installs), not AST parsing. Cheap, dependency-free, and
  sufficient for the "detects a capability is present" heuristics in §7 —
  it can false-negative on heavily obfuscated code, which is an accepted
  v1 limitation for a static linter, not a security boundary.

## Phase 2 — Engine + 3 flagship checks

- **The `Check` contract lives in `engine/types.ts`, not `engine/index.ts`.**
  Every check module imports `Check`; if it were defined in
  `engine/index.ts` (which imports `checks/index.ts` to build the default
  registry), that would create an import cycle. `engine/types.ts` is a leaf
  module both sides can depend on.
- **`engine/index.ts` stays pure — no I/O, no `checks/index.ts` import,
  no default registry.** `runChecks(model, checks, options)` just takes
  whatever `Check[]` it's given. Wiring discovery → the `ALL_CHECKS`
  registry → a reporter happens in `cli.ts`, matching the "cli.ts: entry
  point, arg parsing, **wiring**" comment in the §6 project-structure
  listing and keeping the engine trivially testable with fake checks (see
  `test/engine/runChecks.test.ts`).
- **CHAP-AGY-001's "no allowlist" half of the heuristic is simplified to
  "shell capability detected".** Per the Phase 1 decision above, the
  `Skill` model doesn't track a command allowlist/confirmation gate yet
  (deferred until a check needs it, to avoid guessing an unused manifest
  schema). Since it's now Phase 2 and this check is the one that would
  consume that field, the honest v1 behavior is documented here rather
  than silently assumed: any detected `shellExec` capability fires,
  because "no allowlist" can't yet be distinguished from "has an
  allowlist". Revisit if/when a real allowlist convention is added to the
  Skill model.
- **Finding `location.line` is always `null` in v1.** `configParser.ts`
  parses YAML/JSON into a plain value tree without retaining source
  position info, so checks can only report a file path + a semantic
  `detail` (the config key path, e.g. `llm.api_key`, or a skill name)
  rather than a line number. This matches the "file + path/line **where
  possible**" wording in §9; tracking real line numbers (e.g. via
  `YAML.parseDocument`'s node ranges) is a possible future enhancement,
  not required for v1.
- **`picocolors` for console color**, per the §4 suggestion. It
  auto-detects a non-TTY stream and `NO_COLOR`/`FORCE_COLOR` and disables
  itself accordingly, so "must degrade gracefully on a plain terminal"
  (§9) is satisfied without any extra flag-handling code; the explicit
  `--no-color` CLI flag itself is still Phase 5 work (an override for
  users who want it even on a color-capable TTY).
- **`ScanMetadata` (target/timestamp/tool version/inspected+skipped counts)
  lives in `reporters/types.ts`, not `model/types.ts`.** It describes the
  scan run/report, not discovered agent data, so it isn't part of the
  `AgentModel`/`Finding` zod schemas — but it's still one shared type so
  the JSON/SARIF reporters added in Phase 4 reuse the exact same shape
  instead of redefining it.
- **Posture score is intentionally not implemented yet.** §9 mentions a
  score as part of the console reporter's output, but §12 explicitly
  assigns "posture score" to Phase 4 alongside the JSON/SARIF reporters
  and `--fail-on`. Building the scoring formula now, before Phase 4 needs
  it, would jump ahead of the phase plan; the Phase 2 console reporter
  prints a per-severity count summary instead.
- **Removed `discovery/inventory.ts` (the Phase 1 raw-inventory dump).**
  It was explicitly a stand-in "before the check engine and real reporters
  exist"; now that `chaperone scan` prints real findings via the console
  reporter, the old dump had no caller and no test — dead code, deleted
  rather than left unused.

## Phase 3 — Full check set

- **Extended the `Skill` model exactly where Phase 1 deferred it.** The
  Phase 1 note said "extend `Skill`/`GatewayModel` once the actual
  heuristic is known" rather than guess ahead of the consuming check.
  Phase 3 is that moment for CHAP-AGY-002/003/004: added
  `capabilities.fileSystemScoped` (computed in `skillsScanner.ts` from the
  same source-regex pass as the other capabilities — evidence of
  `path.join(__dirname, ...)`/`.resolve(__dirname, ...)` or a
  `WORKSPACE`/`SANDBOX`/`SCOPED`-named constant), `confirmationRequired`,
  and `domainAllowlist` (both read from the manifest, top-level or nested
  under a `capabilities` sub-object — again an invented-but-documented
  convention, no real schema exists for these example agents). Also added
  `AgentModel.recoverability.killSwitchDocumented` for CHAP-OBS-003 (a
  small new discovery module, `recoverability.ts`, checking for a
  `KILL_SWITCH.md`/`STOP.md`/`kill-switch.sh`/`revoke.sh` at the target
  root).
- **`.gitignore` pattern matching (deferred from Phase 1) implemented as
  pure logic in `checks/shared/gitignoreMatch.ts`**, consumed only by
  CHAP-SEC-002. Deliberately a small subset of real gitignore semantics
  (`*`/`?` wildcards, directory-only and root-anchored patterns, `!`
  negation processed in order) — no `**`, no nested (non-root)
  `.gitignore` files. Documented as a known gap rather than attempting a
  full implementation for one check's heuristic.
- **`channels`/`trust` config sections are read directly from
  `model.config.data` by CHAP-INJ-001/003/004**, via small accessor
  helpers in `checks/shared/configAccess.ts`, rather than becoming
  dedicated `AgentModel` fields. This follows the Phase 1 decision
  exactly: neither concept is one of instruction.md §8's six buckets, and
  reading an already-parsed in-memory tree is pure data traversal, not
  I/O, so it's legitimate to do straight in a check.
- **`trust.tool_allowlist`** (CHAP-INJ-003) is a new invented config
  field, same caveat as the manifest conventions above — added to both
  fixtures (empty in vulnerable, populated in clean) since no check
  previously needed it.
- **CHAP-SUP-003's heuristic is deliberately weak, per instruction.md §7's
  own text**, not a shortcut taken here: no outbound advisory-API calls
  are allowed (§14), so v1 just surfaces every dependency manifest and
  points at `npm audit`. It fires on the clean fixture's three skills too
  (they all have a `package.json`) — this is the correct, spec-mandated
  v1 behavior, not a bug. Documented prominently in `CHECKS.md` and in the
  check's own test file so it isn't mistaken for one later.
- **CHAP-INJ-002's heuristic is a static proxy, not real data-flow
  analysis.** "A tool's output can trigger another tool with no
  validation step" isn't something a static scanner can confirm without
  tracing actual data flow. v1 flags the _shape_ of that risk instead: a
  skill that both ingests external/tool data (network or filesystem
  capability) and can execute shell commands. Documented as a proxy, not
  a confirmed finding, in both `CHECKS.md` and the check's own doc
  comment.
- **Permission-dependent checks (CHAP-SEC-003, and CHAP-SEC-004's
  world-readable-log branch) are NOT asserted against the named fixtures'
  checked-out state**, continuing the Phase 1 policy: git only preserves
  the executable bit, so 0600 vs 0644 isn't portable across machines/CI.
  Each has its own isolated temp-dir test with explicit `chmod`
  (`test/checks/chapSec003.test.ts`, `test/checks/chapSec004.test.ts`).
- **The Phase 3 "runs on both fixtures" integration test
  (`test/scan/fullCatalog.test.ts`) copies each fixture to a temp dir and
  chmod's `config.yaml`/`logs/agent.log` explicitly (0644 for the
  vulnerable copy, 0600 for the clean copy) rather than running against
  the committed fixtures directly**, for the same permission-portability
  reason, and to avoid ever mutating the real working tree during a test
  run. The copy also has to fabricate a `.git` directory and a
  `.gitignore`: CHAP-SEC-002 depends on the fixture sitting inside a real
  git repo, which is true for the _committed_ fixtures (they live inside
  Chaperone's own repo) but not for a bare temp-dir copy. A plain
  `chaperone scan` against the committed fixtures will still show
  CHAP-SEC-003/004 findings that depend on the machine's actual
  checked-out permissions — expected and accurate, not a defect.
- **Word-boundary gotcha in the destructive-keyword regex
  (`\bdelete\b`, `\bsend\b`, ...): a camelCase identifier like
  `deleteFile`/`sendMessage` does NOT match**, since there's no
  non-word-character boundary between `delete`/`send` and the following
  capital letter. The `file-writer` and `messenger` fixture skills
  reference the standalone words in their code comments so
  CHAP-AGY-003 has real true-positive/true-negative fixture coverage; a
  real target agent's skill would need the keyword to appear as a
  genuinely standalone word too (e.g. snake_case or a doc comment) to be
  detected in v1 — a known heuristic limitation, not fixed here to avoid
  scope creep into a smarter tokenizer for one check.

## Phase 4 — Reporters + exit codes + score

- **Posture score weights/bands (critical 25, high 15, medium 7, low 3,
  info 0; A/B/C/D/F at 90/75/60/40/0) are an original, documented
  formula** — §9 only specifies the shape ("start at 100, subtract
  weighted points per finding by severity, floor at 0... show the score
  and a letter/band"), not exact numbers. Chosen so a single critical
  finding alone drops a full letter band (100 -> 75, A -> B) and a
  handful of real issues meaningfully move the score, while `info`
  findings (currently only an internal check-error record) never affect
  it. Documented in `CHECKS.md` per the "keep the formula transparent"
  instruction, and enforced (not just described) by the score assertions
  in `test/scan/fullCatalog.test.ts` and `test/engine/severity.test.ts`.
- **CHAP-SUP-003's known weak heuristic (Phase 3) now visibly taxes the
  score too**: the clean fixture scores 55 (band D), not 100, purely from
  three High findings that only ever say "run npm audit yourself."
  Surfaced explicitly as a caveat in `CHECKS.md` rather than adjusting
  the check's severity to make the score look better — severity is
  spec-assigned per check ID, not tunable to flatter a demo score.
- **JSON report schema lives in `reporters/schema.ts`, separate from
  `model/types.ts`.** It's the _reporter output_ shape (tool info +
  summary/score + findings + counts), not part of the `AgentModel`/
  `Finding` data model those schemas describe — same reasoning as
  `ScanMetadata` living in `reporters/types.ts` since Phase 2.
  `formatJsonReport` calls `ScanReportSchema.parse()` on every report
  before emitting it, so "schema-stable" (§9) is a runtime guarantee, not
  just a documented shape.
- **SARIF reporter derives its `rules` array from the findings it's
  given, not from the full `ALL_CHECKS` registry.** Every field a SARIF
  rule needs (title, category, OWASP mapping, severity) is already on
  each `Finding`, so `sarif.ts` stays a pure function of `Finding[]` +
  `ScanMetadata` — consistent with "reporters are pure formatters" (§5) —
  rather than taking the check registry as an extra input. The trade-off:
  a check that produced zero findings in this run won't appear in
  `rules`, which is acceptable (and arguably more useful) for a
  per-scan SARIF upload.
- **SARIF reporter tests are structural assertions against the 2.1.0
  shape, not full JSON-Schema validation.** Pulling in a JSON-Schema
  validator (or vendoring the ~1500-line official SARIF schema) to
  validate a hand-built, dependency-free reporter would work against the
  "minimal dependencies" instruction (§4) for one reporter's tests. The
  structural checks (`$schema`, `version`, `runs[0].tool.driver.{name,
version,rules}`, `results[].{ruleId,level,message}`, correct
  severity->level mapping) cover the shape GitHub code scanning actually
  needs.
- **`formatConsoleReport` takes an optional `{ color: boolean }`, default
  true (picocolors auto-detection).** Needed for `--output`: baking ANSI
  codes into a saved report file is almost never wanted, so the CLI
  passes `{ color: false }` whenever `--output` is set, regardless of
  format. Implemented as an explicit option rather than relying on
  picocolors' own env-var detection timing, which is unclear once the
  module has already been imported.
- **`--fail-on`/`--format` values are validated via commander's
  `InvalidArgumentError`**, which (by commander's own default behavior,
  unchanged here) prints a clear error and calls `process.exit(1)` on a
  bad value. That path is intentionally **not** covered by an in-process
  test (`test/cli.exitcode.test.ts`): calling `run()` with a bad value in
  the same process as the test runner would really call `process.exit()`
  and kill the vitest worker mid-suite. Verified manually instead (`node
dist/cli.js scan ... --format xml` / `--fail-on extreme`, both exit 1
  with a "must be one of: ..." message) — see the runnable-check output
  captured during this phase's development.
- **Exit code uses `process.exitCode = 1`, not `process.exit(1)`,** for
  the `--fail-on` threshold match. This lets `console.log`/`writeFileSync`
  finish flushing before Node exits naturally, and is what makes the
  in-process exit-code tests safe to run at all (setting `.exitCode` is
  just a value assignment, not an immediate process termination).
- **`--only`/`--skip`/`--no-color`/the `checks` subcommand are still not
  wired into the CLI**, even though the engine has supported `only`/`skip`
  filtering since Phase 2. Per §12, those are explicitly Phase 5
  ("Hardening & UX") deliverables, not Phase 4's.

## Phase 5 — Hardening & UX

- **`ScanMetadata` now carries the full `inspected`/`skipped` arrays, not
  just counts.** §9 describes reporter metadata as "(target, timestamp,
  **inspected/skipped inventory**, tool version)" — Phase 2 had
  under-implemented this as bare counts, which meant _why_ nothing was
  found (the actual skip reasons) was silently discarded before it ever
  reached a reporter. Fixed now because it's squarely what "helpful
  messages when nothing is found" (§12) needs: the console reporter lists
  every skipped path + reason, and the JSON schema carries the full
  arrays for automation. This changed `ScanReportSchema` and every
  reporter's `METADATA` test fixture; not a breaking concern since the
  JSON reporter has no external consumers yet.
- **Console reporter distinguishes "could not locate an installation to
  scan" from "scanned and found nothing."** Printing "No findings." when
  `targetRootResolved` is false would read as a clean bill of health for
  a scan that never actually ran — actively misleading for a security
  tool. The distinct message plus the (now-visible) skipped-reason entry
  explains why.
- **`chaperone scan` skips running checks entirely when the target root
  was never resolved**, rather than running the full suite against an
  empty/placeholder `AgentModel`. Caught this via manual testing: a couple
  of checks that don't depend on config (CHAP-OBS-001 "no audit log",
  CHAP-OBS-003 "no kill switch") still fired against a target that
  doesn't exist, producing "findings" about a nonexistent install right
  next to a report saying nothing was found — confusing and wrong. Note
  this guard is specifically for the _no-path-given-and-no-default-found_
  case (`targetRootResolved: false`); an explicit nonexistent path still
  "resolves" structurally (see `resolveTargetRoot`/discovery's
  graceful-degradation tests from Phase 1) and still runs the full suite
  against its empty model — that's existing, correct, tested behavior
  and out of scope here.
- **A scan that never located an install now sets a non-zero exit code**,
  same as hitting `--fail-on`. §9 only defines exit codes in terms of
  findings meeting a threshold, but a CI pipeline reading "0 findings, no
  install found" as exit 0 would silently treat "we scanned nothing" as
  "scan passed" — risky for a security tool, so this path is folded into
  the existing pass/fail exit code rather than inventing a third exit
  code the spec never asked for.
- **`--only`/`--skip` check IDs are validated against the registry up
  front** (`command.error()` on an unknown ID, or when the filters leave
  zero checks to run), rather than silently no-op'ing on a typo. Uses the
  same `command.error()` mechanism (commander's own error formatting +
  `process.exit(1)`) already established for `--format`/`--fail-on` in
  Phase 4, for one consistent "bad usage" convention rather than a second
  exit-code scheme.
- **`--output` write failures are caught and reported cleanly**
  (`command.error()` with the underlying error message) instead of
  crashing with a raw Node stack trace — e.g. writing to a directory that
  doesn't exist. Verified manually (`--output
/nonexistent-dir/report.json` → a clean one-line error, exit 1).
- **None of the above four `command.error()` paths (unknown check ID,
  empty --only/--skip result, --output write failure) have an in-process
  test**, continuing the Phase 4 precedent: `command.error()` calls
  `process.exit()` by commander's own default, and calling that in the
  same process as the test runner would kill the vitest worker mid-suite.
  All four were verified manually during this phase's development
  (captured in the session transcript); `test/cli.options.test.ts` and
  `test/cli.exitcode.test.ts` cover every non-throwing path in-process.
- **Added the `chaperone version` subcommand** (alongside the existing
  `-V`/`--version` flag from `.version()`), closing a gap against §10's
  CLI design table that had been present since Phase 0 — the table lists
  `version` as its own subcommand, not just a flag, and no earlier phase
  had called that out explicitly to catch it.
- **`configLocator.ts`'s `DEFAULT_ROOTS` is now exported** so
  `discovery/index.ts` can build the "no installation found" message
  dynamically (listing the actual paths tried) instead of a static,
  unhelpful string — the two were silently allowed to drift apart before.

## Phase 6 — Docs

- **Added a `LICENSE` file (MIT)** — `package.json` had already declared
  `"license": "MIT"` since Phase 0, but no actual license file existed
  for a public repo claiming one. Low-risk, standard-practice gap-fill,
  not a new decision so much as completing an existing one.
- **README's "Example output" is real, captured CLI output**, trimmed for
  length and with the local absolute path (`/Users/.../vulnerable-agent`)
  swapped for the generic `~/clawd` used throughout the rest of the
  README — not hand-written/invented sample output, so it can't drift
  from what the tool actually prints.
- **README documents known limitations explicitly** (the invented config
  schema, `CHAP-SUP-003`'s weak heuristic, `CHAP-INJ-002`'s proxy
  heuristic, the `.gitignore`-matching subset, no console-visible posture
  score) rather than only the DECISIONS.md log — a reader shouldn't have
  to reconstruct "what does this tool NOT actually do well" by reading
  every phase's rationale.
- **Verified "the repo builds from a clean checkout" (§17) empirically**,
  not just assumed: cloned the pushed `main` branch into a scratch
  directory, ran `npm install`/`lint`/`format`/`typecheck`/
  `typecheck:tests`/`build`/`test` from there, and confirmed `chaperone
scan` works end to end — all before writing the install instructions
  that claim this works, so the README's Install section is exercised,
  not aspirational.
- **§17's "the clean fixture yields none" is not literally true for
  this build, by design** — `clean-agent` yields 3 `CHAP-SUP-003`
  findings, a direct, unavoidable consequence of that check's own
  spec-mandated weak v1 heuristic (§7: no live advisory-API calls
  allowed, so it surfaces every manifest it finds regardless of how
  hardened the install is). This has been documented since Phase 3/4
  (`CHECKS.md`, `test/scan/fullCatalog.test.ts`,
  `test/checks/chapSup003.test.ts`) and is now called out in the README
  too, rather than treated as a discrepancy to silently paper over.

This is v1. Every phase in §12 is complete: scaffold, discovery model,
engine + flagship checks, the full 22-check catalog, all three reporters
with posture score and CI-friendly exit codes, CLI hardening/UX, and this
documentation pass. §17's definition of done holds, with the one
consequence of `CHAP-SUP-003`'s spec-mandated heuristic noted above.

## Post-v1 — npm publish prep

- **Package renamed to the scoped `@alpayaltuntas/chaperone`.** The
  unscoped `chaperone` name is already taken on the public npm registry
  by an unrelated package. `publishConfig.access: "public"` added since
  scoped packages default to requiring a paid account otherwise.
- **Removed the dangling `"main": "./dist/index.js"` field** — a Phase 0
  leftover pointing at a file that was never created (`src/index.ts` was
  never written; this is a CLI-only tool, no library entry point exists).
  Anyone `require()`/`import`-ing the package as a library would have hit
  `MODULE_NOT_FOUND`. Not needed for a `bin`-only package — removed
  rather than stubbed, since there's no actual library surface to expose.
- **Added `repository`/`homepage`/`bugs`/`keywords`** — standard npm
  registry metadata, populated with the real GitHub repo URL now that one
  exists.
- **Caught a real, publish-blocking bug via the actual packaging
  pipeline, not just `npm run build`/tests: `chaperone` silently did
  nothing (no output, exit 0) when installed as a real package.**
  `npm install` creates a symlink at `node_modules/.bin/chaperone` →
  `dist/cli.js`. `process.argv[1]` is that literal symlink path; Node's
  ESM loader resolves `import.meta.url` through the symlink to the real
  file. The original `isMainModule` check compared the two with a naive
  string equality, which only ever matched when invoking `node
dist/cli.js` directly (every manual test throughout this build) — never
  through the symlink npm actually creates. No unit test caught this
  either: every existing CLI test calls `run()` directly, bypassing
  entrypoint detection entirely.
  Only surfaced by the most rigorous check available short of actually
  publishing: `npm pack` → install the real tarball into an isolated
  temp project → run the installed binary. That's now a standing
  pre-publish step, not a one-off — see the README's contributing notes
  for how to redo it after any CLI change (`npm pack`, install the tgz
  into a scratch dir, run the `node_modules/.bin/chaperone` binary).
  Fixed by resolving both sides through `realpathSync` before comparing,
  and refactored `isMainModule` to take `(entryPoint, moduleUrl)` as
  parameters — dependency-injected rather than reading
  `process.argv`/`import.meta.url` directly — specifically so this exact
  symlink-resolution logic is unit-testable
  (`test/cli.mainModule.test.ts`) without needing a subprocess or a real
  npm install every time. That test's own fixtures had to build their
  expected `moduleUrl` through `realpathSync` too, for the same reason
  (macOS resolves `/tmp` → `/private/tmp`) — the same class of bug, one
  level up, caught while writing the regression test for the first one.
- **Package renamed a second time, to `@alpay_altuntas/chaperone`** (with
  the underscore). `@alpayaltuntas/chaperone` — assumed by analogy with
  the GitHub username `AlpayAltuntas` — turned out wrong: an npm user's
  personal scope must exactly match their actual npm username, which is
  `alpay_altuntas` (confirmed via `npm whoami`), not their GitHub handle.
  The mismatch wasn't caught by any local check (`npm pack`/tarball-install
  verification doesn't touch the real registry) — only surfaced as a 404
  on the real `npm publish` PUT once actual registry auth was in play.
  Fixed by correcting `package.json`'s `name`, regenerating
  `package-lock.json`, and re-verifying the full suite before retrying.
- **Published `@alpay_altuntas/chaperone@0.1.0`** to the public npm
  registry. Authenticated via a granular access token (publish
  permission, all packages, no organization access, 2FA bypass enabled)
  rather than interactive OTP entry, since this session can't respond to
  an interactive `Enter OTP:` prompt mid-command — the token was set in
  the user-level `~/.npmrc` (never the project's committed one) and
  removed again immediately after a successful publish. Verified with the
  most rigorous check available: installed the package fresh from the
  live public registry into an isolated scratch directory and ran the
  installed binary (`--version`, `scan`) before calling it done.

## Improvement plan, Phase 1 — Correctness bug fixes

Seven fixes from `improvement_plan.md` Part 1, found by rereading every
discovery module and check rather than staying at the architecture level.
Each has a dedicated regression test; see the item numbers below.

- **`1.2`: `SECRET_KEY_PATTERN` replaced with segment-based matching**
  (`looksLikeSecretKeyName` in `configParser.ts`). The old substring
  regex only recognized the literal sequence `api_key` for the whole
  "key" family — `private_key`, `ssh_key`, `encryption_key`, and every
  other ordinary `*_key` name were invisible to every secrets check —
  while simultaneously false-positiving on any word merely _containing_
  "token"/"secret"/etc. (`tokenizer_model`, `secretary`). Fixed by
  splitting a key into segments on `_`/`-`/camelCase boundaries and
  checking whole-segment membership in a small word set, which closes
  both the false-negative and false-positive gap at once rather than
  patching the regex into something even harder to reason about.
- **`1.3`: `CHAP-NET-001` now checks the real loopback range**
  (`isLoopbackAddress` in `chapNet001GatewayExposed.ts`), not a 3-item
  literal set. All of IPv4 `127.0.0.0/8` is loopback, and IPv6 loopback
  has multiple valid textual forms (`::1`, `0:0:0:0:0:0:0:1`, ...) — the
  old check false-positived a critical finding on any of them other than
  the two canonical spellings. Deliberately not a full RFC-grade IPv6
  parser (e.g. IPv4-mapped `::ffff:127.0.0.1` isn't recognized) — covers
  the realistic config-value cases without over-building.
- **`1.4`: `~`/`~/...` paths in config now expand to the real home
  directory** (`expandHome` in the new `discovery/pathUtils.ts`), applied
  to both `logging.path` and `skills_dir`. `path.resolve` has no concept
  of `~` — it was being treated as a literal subdirectory named "~",
  meaning a config using that (common) convention pointed permission
  checks at a path that silently doesn't exist, no error surfaced.
  `expandHome` takes `homeDir` as an injected, defaulted parameter (same
  pattern as `isMainModule` in `cli.ts`) specifically so it's unit
  testable without mocking `os.homedir()`.
- **`1.5`: env-reference detection recognizes bash/docker-compose default
  syntax** (`${VAR:-default}`, `${VAR:=default}`, `${VAR:?message}`,
  `${VAR:+alt}`), not just bare `${VAR}`. That styling is extremely
  common in real config templating and was previously masked and flagged
  as a literal secret — a false positive on an entirely safe pattern.
- **`1.11`: untrusted skill `name`/`author` are sanitized in discovery,
  not the console reporter** (`stripControlCharacters` in
  `skillsScanner.ts`) — strips CSI/OSC ANSI escape sequences and any
  remaining raw control bytes. Deliberately placed at the discovery
  layer, matching the established "sanitize once, at the trust boundary"
  precedent secret-masking already uses in `configParser.ts`, rather than
  in the console reporter as the improvement-plan entry originally
  suggested: a skill manifest is untrusted content by definition (that's
  what `CHAP-SUP-001` exists to flag), and its `name`/`author` are
  interpolated directly into finding messages with no further escaping
  downstream — sanitizing at the source protects every current and future
  consumer uniformly, not just the console reporter.
- **`1.12`: unexpected errors in the scan pipeline get a distinct exit
  code (`2`)**, not `1` — the same code findings meeting `--fail-on`
  already used, which made "Chaperone crashed" and "Chaperone found real
  issues" indistinguishable to a CI pipeline reading only the exit code.
  The whole `scan` action body is now wrapped in one try/catch. This is
  safe alongside the existing `command.error()` calls (unknown check ID,
  empty `--only`/`--skip` result, `--output` write failure): without
  `.exitOverride()` configured, commander's `.error()` calls
  `process.exit()` directly rather than throwing, so none of those ever
  reach the new catch block. Tested via `vi.mock`'ing `renderReport` to
  throw, in a dedicated test file (`test/cli.unexpectedError.test.ts`) so
  the module mock doesn't leak into other CLI tests that need the real
  reporters.
- **`1.15` (mitigation half): `CHAP-SUP-003` demoted from `High` to
  `Info`.** The real fix (an offline vulnerability database) is a
  separate, much larger effort (`improvement_plan.md` Phase 18) — this is
  the cheap interim step so a check that fires on literally every skill
  with a `package.json`, hardened or not, can't trip `--fail-on high` or
  drag down a genuinely hardened install's posture score on its own. This
  is a deliberate deviation from `instruction.md` §7's stated severity for
  this check — noted here explicitly rather than silently diverging from
  the original spec, since `instruction.md` itself is treated as a fixed
  reference document throughout this project and is never edited. Updated
  everywhere the old severity was baked in: the check itself,
  `CHECKS.md`, and the posture-score assertions in
  `test/scan/fullCatalog.test.ts` (clean fixture: 55/D -> 100/A, since the
  3 `CHAP-SUP-003` findings there now deduct 0 instead of 45).

## Improvement plan, Phase 2 — Repo hygiene & documentation

Items `4.1`, `4.3`, `4.7`, `4.8` from `improvement_plan.md`. Docs only —
no code changes.

- **`CHANGELOG.md`** in Keep a Changelog format, with `[Unreleased]`
  backfilled from Phase 1's seven fixes and a `[0.1.0]` entry
  reconstructed from what actually shipped (dated from the real npm
  publish timestamp, `npm view @alpay_altuntas/chaperone time`, not
  guessed). States the versioning policy explicitly (a new check or a
  severity change is a minor bump minimum) rather than leaving it
  implicit.
- **`SECURITY.md`** names two in-scope report classes explicitly — a bug
  in Chaperone itself (violating its own read-only/no-network/masking
  guardrails) and a false negative that matters (a check silently missing
  something) — since the second is easy to under-value as "just a
  correctness bug" for a tool whose entire purpose is catching things.
  Points at GitHub's private vulnerability reporting as the preferred
  channel; enabled it on the repo (`private-vulnerability-reporting`, was
  off) so the link in the doc actually works.
- **Issue template (bug report) + `config.yml`** prompting for the
  specific fields that actually matter for a heuristic-driven tool (which
  check, expected vs. actual, a redacted repro snippet) rather than a
  blank box; `config.yml` redirects security reports to `SECURITY.md`
  instead of a public issue.
- **PR template** checklist mirrors the actual definition-of-done this
  project has used in every phase so far (fixture pair for a check
  change, `CHECKS.md`/`CHANGELOG.md`/`DECISIONS.md` kept in sync) —
  encoding it once so it doesn't have to be restated per PR.
- **README "How Chaperone relates to other tools"** section (item `4.8`)
  added between "Checks" and "Known limitations". Names gitleaks/
  trufflehog/npm audit/Snyk explicitly rather than being vague about
  "other scanners" — the point is to be honest that Chaperone doesn't
  compete on generic secret/dependency detection, only on the
  agent-specific categories (`CHAP-AGY-*`/`CHAP-INJ-*`/`CHAP-NET-*`/
  `CHAP-OBS-*`) nothing else covers.
- **Caught and fixed a real staleness bug while doing this pass**: the
  README's "Example output" section had hardcoded real captured CLI
  output from before Phase 1's `CHAP-SUP-003` severity demotion — still
  said "17 high, 0 info" and "15 more high-severity findings" (already
  slightly wrong even before Phase 1 — 1 shown + 15 more = 16, not the
  claimed 17). Re-ran the actual scan and corrected both to the current
  real numbers (13 high, 4 info, 12 more). A concrete instance of why
  `DECISIONS.md`'s Phase 6 note ("the README's example output is real,
  captured CLI output... so it can't drift") only holds if it's actually
  re-verified after a change that affects it — noted here so future
  phases remember to check this file too.

## Improvement plan, Phase 3 — CI pipeline hardening

- **Coverage tooling** (`4.5`): added `@vitest/coverage-v8` pinned to the
  exact same version as `vitest` itself (`4.1.11`) — the coverage
  provider and the runner have to be version-matched or vitest refuses
  to run. `vitest.config.ts` scopes `include` to `src/**/*.ts` only —
  `test/fixtures/**` is inert sample data the checks scan, not code this
  project owns, so it has no business in a coverage number. Real
  measured numbers on this pass: 96.43% statements / 83.68% branches /
  98.66% functions / 96.47% lines. `coverage/` added to `.gitignore`
  (generated output, not source).
- **Coverage badge deferred**: `4.5`'s literal definition-of-done
  mentions a README badge. Decided not to wire one up this phase — the
  standard path (Codecov or similar) means granting an external service
  access to the repo, which is a decision the account owner should make
  explicitly rather than one made silently mid-phase. Chose the
  self-contained alternative instead: CI uploads the `coverage/` HTML
  report as a build artifact (`actions/upload-artifact`) on every run,
  so real numbers are inspectable from the Actions tab without a
  third-party integration. Revisit the badge specifically if/when
  wanted.
- **Packaged-binary smoke test in CI** (`4.4`): promotes the manual
  `npm pack` → install-into-temp-dir → run verification (used ad hoc
  during the original npm-publish debugging, see "Post-v1 — npm publish
  prep" above) into an automated CI step that runs on every push/PR.
  Explicitly asserts `chaperone --version` prints non-empty output —
  that exact assertion is the regression guard for the symlink
  entrypoint bug (`isMainModule` comparing `import.meta.url` against
  `process.argv[1]` without resolving npm's bin symlink first), which
  `npm test` alone never exercised because it never runs the actual
  installed binary. Scans `test/fixtures/clean-agent` (not
  `vulnerable-agent`) as the smoke target deliberately — a scan that
  intentionally exits non-zero interacts badly with the default GitHub
  Actions shell (`bash -eo pipefail`), and this step only needs to prove
  the binary runs, not re-assert scan correctness (already covered by
  the test suite).
- **Dependency audit** (`4.6`): `npm audit --audit-level=high` added as
  its own CI step (fails the build on high/critical advisories, not on
  every low-severity noise finding) plus `.github/dependabot.yml`
  covering both the `npm` and `github-actions` ecosystems on a weekly
  schedule, with dev dependencies grouped into one PR rather than one PR
  per dev dependency bump.

## Improvement plan, Phase 4 — Release automation

- **OIDC "trusted publishing" release workflow** (`3.6`): `.github/
workflows/release.yml`, tag-triggered (`v*`) for real releases plus a
  `workflow_dispatch` input (`dry_run`, default `true`) so the whole
  pipeline — lint/format/typecheck/build/test, then `npm publish
--dry-run` — can be exercised on demand without cutting a release or
  needing trusted publishing configured on the npm side yet. Verified by
  triggering the dry-run path directly.
- **Node 22, not 20**: trusted publishing needs at least npm 11.5.1 and
  at least Node 22.14 (confirmed against current npm docs,
  docs.npmjs.com/trusted-publishers/ — not assumed). `ci.yml` stays on
  Node 20 since it has no such requirement; only the release workflow
  needs the newer runtime. Pinned `npm install -g npm@latest` as a
  belt-and-suspenders step rather than trusting whatever npm version the
  Node 22 image happens to bundle.
- **No `--provenance` flag**: per current npm docs, provenance
  attestation is generated automatically under trusted publishing —
  passing the flag explicitly is redundant (harmless but redundant, left
  out for clarity).
- **Tag/version guard**: a real (tag-push) release fails fast if the
  pushed tag (`vX.Y.Z`) doesn't match `package.json`'s version, instead
  of silently publishing a mismatched version.
- **One remaining manual step, outside CI's reach**: trusted publishing
  requires linking `@alpay_altuntas/chaperone` to this repo + workflow
  filename (`release.yml`) via npmjs.com's package settings
  ("Trusted Publisher") — there's no npm API for this, it's a one-time
  web UI action only the package owner can take. Until that's done, a
  real tag-triggered publish will fail at the final `npm publish` step
  (auth); the dry-run path works regardless since it never contacts the
  registry's publish endpoint. This replaces the manual 2FA/access-token
  flow used for the `0.1.0` publish (see "Post-v1 — npm publish prep"
  above) once configured.

## Improvement plan, Phase 5 — Discovery: sidecar secret files + persistent memory/state

- **Sidecar secret files** (`1.6`/`2.2`): discovery now looks for `.env`,
  `.env.local`, `secrets.yaml`, `secrets.yml`, `secrets.json` alongside
  the main config and feeds each one through the exact same masking
  pipeline `config.yaml` already gets (`discovery/configParser.ts`'s
  `maskConfig` — reused as-is, not reimplemented, so the secret-key-name
  heuristic and env-reference detection stay in one place). Closes the
  single biggest real-world blind spot from this pass: a config
  referencing `${API_KEY}` was already safe, but the literal value living
  in a colocated `.env` was previously invisible to every `CHAP-SEC-*`
  check. `.env` parsing is a deliberately minimal, documented-gap
  implementation (`KEY=value`, `#` comments, quote-stripping — no
  multi-line values, no `export` prefix), same precedent as
  `gitignoreMatch.ts`'s partial-gitignore-semantics approach.
- **`CHAP-SEC-006`**: applies CHAP-SEC-002's git-tracking check and
  CHAP-SEC-003's permission check to each sidecar file holding a literal
  secret, combined into one finding (same "combine reasons into one
  message" pattern CHAP-SEC-004 already established) rather than two new
  separate check IDs — the plan allocated one ID for this.
- **Persistent memory/state** (`1.7`/`2.8`): `memory_dir`/`state_dir`
  config field (mirrors `skills_dir`'s existing resolve-and-check
  pattern) closes a real gap against `instruction.md` §2's own scope —
  it lists memory/state as one of five discoverable artifacts, and four
  of five had discovery modules before this; the fifth had none. No
  content inside the directory is ever read, only existence/permissions/
  git-tracking — consistent with the read-boundary discipline elsewhere.
- **`CHAP-OBS-004`**: mirrors CHAP-SEC-002/003 again, applied to the
  memory/state directory. `medium` severity (not `high`, unlike
  CHAP-SEC-006) since there's no literal-secret gate here — arbitrary
  memory content isn't scanned, so this is a general exposure signal, not
  a confirmed-secret one.
- **Fixture strategy**: added `secrets.yaml` + `memory_dir`/`memory/` to
  `vulnerable-agent` only (a true-positive demonstration in the
  full-catalog integration test), left `clean-agent` without them
  (absence is itself a legitimate, trivially-safe configuration) rather
  than fighting this repo's own root `.gitignore` (`.env` is already
  globally ignored there) to construct a "present but safe" fixture —
  the "present but safe" TP/TN matrix is instead covered by dedicated
  isolated-temp-dir unit tests for both new checks (mirroring
  `chapSec002.test.ts`/`chapSec003.test.ts`'s existing pattern), which
  don't depend on or interact with this repo's real git context at all.
- **Caught a test-infra bug while wiring this in**: `chmod`'ing the new
  `memory` directory to a file-style mode (e.g. `0o644`) in
  `fullCatalog.test.ts`'s copy helper stripped the execute bit and made
  the directory untraversable — broke not just the check under test but
  the test's own `rmSync` cleanup afterward (`EACCES, Directory not
empty`). Fixed by deriving a directory-appropriate mode (execute bit
  wherever a read bit is set, e.g. `644` -> `755`) instead of reusing the
  file mode directly.
- **README's example output re-verified and updated again** (real
  captured CLI output, not hand-computed — see the Phase 2 entry above
  for why this matters): 22 -> 24 checks, 35 -> 37 findings, 13 -> 14
  high, 14 -> 15 medium, 13 inspected paths (was 12).

## Improvement plan, Phase 6 — New standalone checks

- **`CHAP-SEC-005`** (`2.1`/`1.8`): a new `discovery/logContentScanner.ts`
  reads up to the last 256 KiB of the log file (bounded — this is a
  security tool auditing files that could themselves be huge or
  adversarial) and scans it for `key=value`/`"key": "value"`-shaped
  substrings whose key matches the existing `looksLikeSecretKeyName`
  heuristic, capped at 20 matches. Reuses `configParser.ts`'s key-name
  and masking logic rather than the plan's alternative
  (a generic high-entropy-string scanner) — picking one, documented,
  same precedent as CHAP-SUP-003's deliberately-simple v1 heuristic.
  Matched values are masked (`maskSecretValue`) before ever reaching the
  model; the real value is never retained, same guarantee config secrets
  already get. Distinct from CHAP-SEC-004/CHAP-OBS-002, which only
  reason about whether logging _will_ leak going forward — this is
  evidence something already did.
- **`CHAP-SEC-007`** (`2.3`): checks whether a bare `${VAR}`/`$VAR`/
  `env:VAR` config reference resolves to anything in Chaperone's own
  `process.env` at scan time. Explicitly advisory — the plan calls for
  the caveat to be "in its own message text, not just CHECKS.md" since
  Chaperone runs as a separate process and may not share the agent's
  real environment (e.g. a systemd/launchd `EnvironmentFile`); the
  finding message states this directly. `low` severity reflects that
  low confidence. Only bare references are checked — a `:-`/`:=`/`:?`/
  `:+` fallback/default resolves to something even when the variable
  itself is unset, so `configParser.ts`'s new `extractEnvVarName`
  returns `null` for those and the check silently skips them rather
  than risk a false positive.
- **A real interaction this surfaced**: `clean-agent`'s config uses
  indirect env-var references by design (`${ANTHROPIC_API_KEY}`,
  `env:TELEGRAM_BOT_TOKEN`, `env:GATEWAY_AUTH_TOKEN`) — meaning
  `CHAP-SEC-007` would fire against it in `fullCatalog.test.ts` in any
  environment where those three vars happen not to be set (true almost
  everywhere, but not guaranteed — a real `ANTHROPIC_API_KEY` set in a
  developer's own shell would have silently changed the test's outcome
  depending on who ran it). Fixed by having the test explicitly
  `vi.stubEnv` those three variables as set before running the
  clean-agent full-catalog scan — the honest scenario for a genuinely
  hardened install (the operator has these set for the agent process
  itself), and makes the test fully deterministic regardless of the
  running environment's ambient state.
- **Fixture strategy**: appended one dummy leaked-secret log line to
  `vulnerable-agent/logs/agent.log` (TP for CHAP-SEC-005 in the
  full-catalog integration test); `clean-agent`'s log stays untouched
  (TN via absence). Full TP/TN matrix for both new checks — including
  the "present but safe" cases — lives in dedicated isolated-temp-dir
  unit tests, same strategy as Phase 5.
- **README's example output re-verified again**: 24 -> 26 checks, 37 ->
  38 findings, 14 -> 15 high, 14 -> 15 paths inspected.

## Improvement plan, Phase 7 — CLI UX round 2

- **`--only-category`/`--skip-category`/`--min-severity`** (`3.8`) are
  explicitly _display_ filters — they filter the findings passed into
  `renderReport`, so the report artifact (console/json/sarif alike) is
  self-consistent with whatever was filtered, including its own
  score/summary. `--fail-on` deliberately reads the full, unfiltered
  `findings` from `runChecks` instead — never the filtered view — so a
  narrow `--only-category`/`--min-severity` for a quick look can never
  accidentally mask a real failure from CI. Tested explicitly in
  `cli.exitcode.test.ts` (filtering the display to a clean category/high
  severity doesn't change the exit code when a real high/critical finding
  exists outside that filter).
- **`--quiet`/`--summary-only`** (`3.11`) are console-reporter-only
  (accepted regardless of `--format`, but only `console` interprets
  them — json/sarif are already structured/compact) and declared
  mutually exclusive via commander's `Option#conflicts()` rather than
  manual validation in the action body.
- **Posture score added to the console reporter's summary line** as part
  of `3.11` (`--summary-only`'s whole point is "summary line + score") —
  previously JSON-only, noted in CHECKS.md as "a possible future
  enhancement". Shown in every console-format run now, not just
  `--summary-only`, since there's no reason to hide it in full-detail
  mode once it exists.
- **Environment-variable support** (`3.12`): `CHAPERONE_FORMAT`,
  `CHAPERONE_FAIL_ON`, `CHAPERONE_OUTPUT`, `CHAPERONE_ONLY_CATEGORY`,
  `CHAPERONE_SKIP_CATEGORY`, `CHAPERONE_MIN_SEVERITY` via commander's
  `Option#env()`. Deliberately did _not_ wire env vars for `--only`/
  `--skip` (check-ID lists — a less common CI-config shape) or the
  boolean flags (`--quiet`/`--summary-only`/`--no-color` — env-var
  boolean parsing is its own can of worms commander doesn't handle
  specially, and none of these were named in the plan's own examples).
  An explicit CLI flag always overrides its env var (commander's default
  precedence), verified in `cli.options.test.ts`.

## Improvement plan, Phase 8 — Generated docs

- **`CHECKS.md` is now generated, not hand-maintained** (`4.2`): every
  check in `src/checks/*` gained three new required `Check` interface
  fields (`detects`/`heuristic`/`remediation` — general, non-interpolated
  doc text, distinct from a `Finding`'s own per-instance `message`/
  `remediation`) plus an optional `severityNote` (used only by
  CHAP-SUP-003's "Info, demoted from High" case). `scripts/
generateChecksDoc.ts` renders the full catalog from `ALL_CHECKS`,
  formats it through Prettier's own API (`prettier.format`, not just the
  CLI) so the generated file is guaranteed `prettier --check`-clean
  without hand-tuning line wraps to match, and writes or (`--check`)
  diffs against the committed file. `npm run docs:checks:check` is now a
  CI step — a hand-edit to CHECKS.md or a new/changed check without
  regenerating fails the build.
- **This immediately caught a real, pre-existing drift**: CHAP-AGY-003's
  hand-written CHECKS.md heading said "Destructive/irreversible action
  without confirmation", but the check's actual `TITLE` constant (used
  everywhere else — findings, `chaperone checks`) was "Destructive action
  without confirmation". The generator surfaced and fixed this
  automatically — exactly the class of bug this phase exists to
  eliminate, found on the very first real run.
- **OWASP display transform**: the check's own `owasp` field uses a colon
  (`'LLM06: Sensitive Information Disclosure'` — the literal string used
  verbatim in `Finding.owasp` across every report format), but CHECKS.md
  has always displayed it with an em dash. Handled as a pure display
  transform in the generator (`replaceAll(': ', ' — ')`, not
  `replace` — CHAP-INJ-003's OWASP value has two colons to convert, e.g.
  `LLM01: Prompt Injection / LLM08: Excessive Agency`) rather than
  changing the underlying data everywhere it's used.
- **Long single-line paragraphs, not manually 80-col-wrapped prose**: the
  previous hand-written CHECKS.md had prose manually wrapped at ~80
  columns; Prettier's default `proseWrap: preserve` doesn't auto-wrap
  long lines, so the generated file's bullet paragraphs are now single
  long lines per field. Still fully `prettier --check`-valid (verified),
  renders identically on GitHub (which always soft-wraps within list
  items regardless of source line length), and is simpler/more robust to
  generate than replicating manual wrapping — accepted as the right
  tradeoff for a generated doc.
- **`chaperone explain <check-id>`** (`3.7`) reads the exact same
  `detects`/`heuristic`/`remediation`/`severityNote` fields the generator
  reads, so the CLI and CHECKS.md literally cannot drift apart — same
  source, two renderers.
- **`generateChecksDoc.ts` reuses `isMainModule`** (imported from
  `src/cli.ts`) for its run-as-script vs. run-as-module guard, rather
  than reimplementing the same symlink-resolution logic a second time —
  and exports the pure `generateChecksDoc()` function so
  `test/scripts/generateChecksDoc.test.ts` can assert against it
  directly (including a byte-for-byte regression check against the
  committed `CHECKS.md`) without shelling out or touching disk.
- **`scripts/` added to `tsconfig.eslint.json`'s `include` and
  `eslint.config.js`'s `files`** — the new script gets the same
  typecheck/lint bar as `src/`/`test/`, not a second-class exemption.

## Improvement plan, Phase 9 — Additional reporters

- **`--format markdown`** (`3.9`): a single sorted-by-severity table
  (`| Severity | Check | Message | Location |`) plus the same summary/
  score line the console reporter has — cheaper to build than a full
  HTML reporter and directly useful for the CI use case the README
  already documented (post as a PR comment via `gh pr comment
--body-file`). Table cells escape `|` (would otherwise break the
  table) and collapse `\n` to a space (a literal newline breaks a
  Markdown table row) — defensive, since a scanned skill/file name could
  legitimately contain either character even though Chaperone's own
  generated prose never does.
- **`--format gha`** (`3.9`): GitHub Actions `::error file=...::`/
  `::warning::`/`::notice::` workflow commands, one per finding, plus a
  trailing `::notice::` summary line. Complements SARIF rather than
  replacing it — inline annotations with zero extra CI steps (no upload
  action needed), vs. SARIF's code-scanning-tab integration. Implements
  GitHub's two-tier escaping exactly as documented: message _data_ only
  needs `%`/`\r`/`\n` escaped, but property _values_ (like `file=`/
  `title=`) additionally need `:`/`,` escaped, since those are the
  property-list delimiters — verified with a dedicated test for a title
  containing both a colon and a comma.
- **Both formats reuse `engine/severity.ts`'s `compareSeverity`/
  `computeScore`** rather than re-deriving severity order or score
  math locally — same precedent as the console/JSON reporters, avoids a
  second source of truth for "which severity is worse" ever existing.
- **GHA `file=` paths are whatever `Finding.location.filePath` already
  is** (an absolute path resolved from the scan target), not made
  relative to `GITHUB_WORKSPACE`. Reporters are pure functions of
  `Finding[]`/`ScanMetadata` with no environment awareness (established
  architecture — see Phase-1-era `engine/types.ts` docstring); computing
  a workspace-relative path would need injecting CI environment context
  into a reporter, which breaks that purity for a benefit that only
  matters when the scan target is checked into the same repo the
  workflow runs in. Documented as a known limitation rather than solved.
- Both formats tested against both fixtures (`cli.exitcode.test.ts`, per
  the phase's definition of done), plus dedicated unit tests for each
  reporter module. README's format table, `--format` examples, and the
  CI-usage section (`gh pr comment`/inline-annotation examples) updated.

## Improvement plan, Phase 10 — AST-based capability detection (foundation)

- **TypeScript's own compiler API, not a lighter JS-only parser**
  (`1.1`, the plan's two named options). `typescript` was already a
  trusted dependency in this codebase's own tooling (build, typecheck,
  the docs generator's formatting doesn't need it, but lint/typecheck
  do) — reusing `ts.createSourceFile`/AST walking avoids introducing an
  entirely new, unvetted third-party parser (acorn/meriyah) while
  handling both `.js` and `.ts` skills with the exact same parser
  (a JS-only parser would still have needed a _second_, TS-capable
  parser for `.ts` skills — SOURCE_EXTENSIONS already includes `.ts`).
  `typescript` itself has zero npm dependencies of its own, so this adds
  no transitive dependency surface.
- **`typescript` moved from `devDependencies` to `dependencies`** — it's
  now used at runtime (`skillsScanner.ts` parses skill source on every
  real scan), not just at build time. Real, honestly-measured cost:
  ~23 MB added to a consumer's `node_modules` (verified via a real
  `npm pack` → install → run cycle, not assumed). The published tarball
  itself is unaffected (still ~84 KB — `typescript` is a separate
  declared dependency npm installs alongside Chaperone, not bundled into
  it). Accepted as the right trade-off: the plan explicitly frames this
  as "nearly everything in the agency/injection categories inherits this
  layer's confidence" — accuracy here is high-leverage enough to justify
  the install-size cost, and the alternative (a second, unvetted parser
  dependency) isn't actually smaller in real terms once a TS-capable
  parser is included too.
- **Binding tracking, not text matching**: a first pass over each file's
  AST collects real `import`/`require` bindings into a small map (local
  name -> {module, namespace-or-named, original export name}), then a
  second pass matches `CallExpression`s against those bindings — a bare
  call (`exec(x)`), a property-access call (`cp.exec(x)`), and a
  string-literal element-access call (`cp['exec'](x)`, the exact dynamic-
  access false-negative `improvement_plan.md` 1.1 named) are all
  resolved back to `{module, functionName}` the same way. An aliased
  named import (`import { exec as run } from 'child_process'`) resolves
  through to the _original_ exported name, not the local alias, so `run(x)`
  is still recognized as `child_process.exec`.
- **The word-boundary bug is fixed by reusing (not duplicating) the
  segment-splitter `configParser.ts` already built** for
  `looksLikeSecretKeyName` (`private_key`/`ssh_key` not matching a bare
  substring regex). Extracted the shared algorithm into
  `discovery/wordSegments.ts` (`splitWordSegments`) — both callers had
  the exact same underlying problem ("does this identifier contain a
  specific whole word as one of its camelCase/snake_case parts"), so
  duplicating it a second time for destructive-keyword identifier
  matching would have been the wrong call. `deleteFile`/`sendMessage`
  now correctly match `delete`/`send` as real identifier segments.
- **Comments and string literals are structurally invisible to this
  detector** — a real, immediate side effect of walking an AST instead
  of matching text: `// this skill can delete files` no longer trips
  anything, because a comment isn't a node the walk ever visits. This
  directly fixes the false-positive class `improvement_plan.md` 1.1
  named, and is _why_ the `file-writer`/`messenger` fixtures could
  previously "pass" the destructive-keyword check via a comment
  containing the word standalone, independent of whether the real code
  (`deleteFile`/`sendMessage`) would have matched a correct word-boundary
  check at all — a tell the fixture was accidentally testing the wrong
  thing. Reworded both comments to remove the coincidental keyword
  overlap entirely (`deleteFile` "erases" now, `sendMessage` "dispatches"
  now) and re-ran the full suite to confirm detection still fires from
  the real function names alone, not fixture prose.
- **A deliberate behavior tightening, not just a parity port**: the old
  `NETWORK_PATTERNS` included a plain `require(['"](?:https?|node-fetch|axios)['"])`
  regex, meaning merely _importing_ `http`/`https`/`axios`/`node-fetch` —
  with zero actual usage — was already enough to flag `networkAccess`.
  The AST version requires an actual call _through_ the tracked binding.
  Stricter, and arguably more correct ("capability" should mean
  something is exercised, not merely imported) — verified this doesn't
  regress either fixture (no fixture relies on import-only detection;
  both real network-capable skills call `fetch(...)` directly), and
  added an explicit regression test (`does not fire merely from
importing a network module with no call through it`) to lock in the
  new, intentional behavior.
- **Known, documented remaining gaps** (not solved — real data-flow
  analysis is out of scope for a static single-file AST pass): arbitrary
  indirection (`const run = exec; run(cmd)` — an identifier reassigned to
  a tracked binding isn't itself tracked), a capability invoked via a
  function reference passed across files/modules, and a fully dynamic
  `require(someVariable)` where the module name isn't a string literal.
  All three were already blind spots for the old regex approach too
  (arguably worse ones, since regex has no binding concept at all) — not
  a regression, just an explicitly acknowledged limit of this
  foundation rather than a claim of completeness.
- **All existing agency/injection checks verified equivalent** against
  both fixtures: the full test suite (357 tests, pre-Phase-10) passed
  unchanged the moment the AST implementation replaced the regex one —
  no finding-count assertions needed updating anywhere, including
  `test/scan/fullCatalog.test.ts`'s exact per-check counts. 42 new tests
  added (`astCapabilities.test.ts`, `wordSegments.test.ts`) covering
  every binding shape, the word-boundary fix, comment/string-literal
  immunity, and the tightened network-import-vs-call distinction.

## Improvement plan, Phase 11 — New checks unlocked by AST work

- **`CHAP-SUP-005`** (`2.6`): flags any `eval()`/`Function()` use
  (bare or `new Function(...)`) unconditionally, regardless of what's
  passed to it. A decode-then-execute chain like `eval(atob(payload))`
  needs no special-case pattern — it's already covered as a call whose
  argument happens to itself be a call, so flagging eval/Function at all
  is a strict superset of the specific example the plan named. `critical`
  severity: dynamic evaluation is at least as serious a smell as
  unrestricted shell execution (also `critical`), and a real backdoor
  hidden this way is, by construction, invisible to every other static
  check.
- **`CHAP-SUP-006`** (`2.7`): a bundled ~100-name reference list of
  well-known npm packages (`checks/shared/popularPackages.ts`) plus a
  from-scratch Levenshtein distance implementation
  (`checks/shared/levenshtein.ts` — no new dependency; classic O(n·m) DP,
  ~25 lines) — deliberately no live registry lookup, preserving the
  no-network guardrail (§14) the plan explicitly calls out. Flags a
  dependency name only when it's _not_ itself on the list (an exact
  match is the legitimate case), is at least 4 characters, and has edit
  distance 1-2 from a list entry (also length-floored at 4, to avoid
  noise from very short names where a small edit distance is common and
  meaningless). `SkillDependencyInfo` gained a `names: string[]` field
  (package.json's `dependencies` keys) — discovery's job, not the
  check's, per the established "checks are pure, no I/O" architecture.
- **`1.16`'s data-flow improvement to `CHAP-INJ-002`**: added a bounded,
  intra-file taint-propagation pass to `astCapabilities.ts`
  (`dataFlowToShellExec`) rather than attempting real cross-function/
  file data-flow analysis, which the plan itself frames as "a genuine
  static-analysis project, not a quick patch." Taint sources are
  network/fs-read call results; taint propagates through simple variable
  assignment and one level of method-call chaining via fixed-point
  iteration (up to 5 passes) over the file's flat variable-declaration
  list — enough to trace the _exact_ shape the `command-relay` fixture
  already demonstrates (`const res = await fetch(url); const command =
await res.text(); exec(command)`), without claiming general
  soundness. When the trace confirms a real chain, `CHAP-INJ-002` now
  reports `high` severity with a "confirmed chain" message instead of
  the previous flat `medium` shape-match; when only the shape-match
  holds (both capabilities present, nothing traced), it stays at the
  original `medium`. Verified against `command-relay` (upgrades to
  `high`) and a new isolated-fixture case with both capabilities but no
  real chain (stays `medium`) — both explicitly asserted in
  `chapInj002.test.ts`, not just implied by absence of failure.
- **`CHAP-INJ-005`** (`2.9`): a new, additive check — deliberately does
  **not** modify `CHAP-INJ-003`'s existing global-allowlist-only logic
  (scope creep beyond what this item asked for). Invented convention
  (documented, no real schema exists — same caveat as CHAP-AGY-003/004):
  `channels.<name>.public` (missing defaults to `true`/untrusted, the
  same conservative-default posture `CHAP-INJ-001` already takes for
  `mark_untrusted_input`) and an optional channel-level
  `channels.<name>.tool_allowlist` override. Fires when at least one
  enabled public channel has no channel-specific override (so it
  inherits the broad global allowlist) while at least one enabled
  private channel also exists — the exact "identical trust treatment for
  a public Discord server and a private admin-only Telegram chat" shape
  the plan named. Two new pure helpers in `configAccess.ts`
  (`getEnabledChannels`), following the established pattern of reading
  `trust`/`channels` straight out of `model.config.data` rather than
  adding a new normalized `AgentModel` field (neither section is
  secret-shaped, and this is pure in-memory traversal, not I/O — see the
  Phase 1 note already on that file).
- **Fixture strategy**: added one new TP fixture skill,
  `vulnerable-agent/skills/plugin-loader` (fetches a payload, decodes and
  `eval()`s it, depends on a typosquatted `reqeust` package) — covers
  `CHAP-SUP-005`/`CHAP-SUP-006` in the realistic full-catalog context and
  incidentally also exercises `CHAP-AGY-004` (no domain allowlist) since
  it fetches. `CHAP-INJ-005` intentionally stayed isolated-temp-dir-only
  (comprehensive TP/TN matrix in `chapInj005.test.ts`) rather than
  reshaping `vulnerable-agent`'s existing channel/allowlist config, which
  is already load-bearing for `CHAP-INJ-003`'s own TP case — changing it
  would have meant re-deriving that check's fixture too, out of scope for
  an _additive_ check. `fullCatalog.test.ts`'s vulnerable-agent counts
  updated from real tool output (44 findings, not hand-computed) after
  adding the fixture — `CHAP-SUP-001/002/003` each +1 (the new skill has
  an unpinned version, no lockfile, and a manifest, same as every other
  skill), `CHAP-AGY-004` +1 (fetches with no domain allowlist).

## Improvement plan, Phase 12 — Real `.gitignore` semantics

- **`ignore` (npm, zero dependencies of its own, ~500 bytes gzipped)
  replaces the hand-rolled matcher** (`1.14`) in
  `checks/shared/gitignoreMatch.ts` — the exact trade Chaperone's own
  minimal-dependencies principle (§4) explicitly allows when correctness
  on a security-relevant check is at stake, rather than hand-rolling
  more glob semantics (`**`, precedence edge cases) that a de facto
  standard library already gets right. Pinned to an exact version
  (`7.0.9`), same convention as every other dependency in this project.
- **`GitContext.gitignorePatterns: string[]` became
  `gitignoreFiles: GitignoreFile[]`** (`{dirRelativeToRoot, patterns}`),
  a real schema change touching `model/types.ts`, `gitContext.ts`,
  `discovery/index.ts`, and all three consuming checks
  (`CHAP-SEC-002`/`006`/`OBS-004`). `gitContext.ts` now walks _down_
  from the git root to `targetRoot` after finding it (not just reading
  the root `.gitignore`), collecting every `.gitignore` at each
  directory level along that chain — real nested-`.gitignore` support,
  the second half of `1.14`'s ask. Deliberately does not walk _past_
  `targetRoot` into its own subdirectories (e.g. a `.gitignore` inside
  `targetRoot/skills/some-skill/`) — every path the three consuming
  checks look at lives at or directly under `targetRoot`, so a
  per-checked-path walk into arbitrary subdirectories would add real
  complexity for cases outside what any check actually needs.
- **Nested-`.gitignore` scoping is a technique layered on top of
  `ignore`, not something the library does automatically**: `ignore`
  matches one flat pattern set against root-relative paths, so a nested
  file's patterns are rewritten before being added to one combined
  matcher — a bare pattern (`foo`) becomes `dir/**/foo` (gitignore's
  `**` matches zero or more directories, so this also covers `foo`
  directly in `dir`), while a rooted or already-multi-segment pattern
  (`/foo`, `sub/foo`) becomes `dir/foo`/`dir/sub/foo`. Verified with
  dedicated tests distinguishing a nested pattern from an
  identically-named root-level one, a nested negation overriding a
  broader root pattern, and root+nested patterns combined.
- **Caught and fixed a real behavioral gap while wiring this in**: the
  `ignore` package only matches a directory-only pattern (`foo/`)
  against a _query_ path that itself carries a trailing slash — passing
  a bare directory name like `memory` against a `memory/` pattern
  silently returns `false`. The old hand-rolled matcher never
  distinguished files from directories at all (a latent inaccuracy that
  happened to make `CHAP-OBS-004`'s existing test pass by accident).
  `isGitignored` gained an explicit `isDirectory` parameter; `CHAP-OBS-004`
  (the only caller checking a directory, not a file) now passes `true`.
  Regression-tested directly (`memory` without vs. with `isDirectory:
true` against a `memory/` pattern).
- **`1.13` decided explicitly, not by omission, per the plan's own
  instruction**: `.git/info/exclude` and a user's global
  `core.excludesFile` are **not** read, and the tracked-vs-untracked
  distinction is **not** implemented. Both would require shelling out to
  `git` (`git check-ignore`, `git ls-files`) — genuinely new I/O surface
  (discovery currently only ever reads the filesystem directly; this
  would be the first external process Chaperone ever spawns), with its
  own real costs: dependence on a `git` binary being present and on
  `PATH`, behavioral differences across git versions, and a categorically
  different failure mode (a hung or misbehaving subprocess) than a
  simple file read can have. Given `1.14`'s `ignore`-package rewrite
  already closes the two biggest, most impactful gaps (`**`, nested
  files) with a small, static, dependency-only change, the marginal
  accuracy gain from subprocess-based git introspection didn't clear the
  bar for the added architectural risk. Revisit if a real install's
  false-positive rate from these specific gaps turns out to matter in
  practice.

## Improvement plan, Phase 13 — Line numbers in findings

- **`YAML.parseDocument` (not `YAML.parse`) is the source of the line
  number** (`1.17`) — `parseConfigSource`'s existing plain-value parse
  discards position info entirely, so a second, CST-aware parse
  (`configParser.ts`'s new `createLineLookup`) runs alongside it rather
  than replacing it. `YAML.LineCounter` converts a node's byte-offset
  `.range` into a 1-indexed `{line, col}` — no manual newline-counting.
  A `keyPath` string like `trust.tool_allowlist[0]` (the same format
  `maskTree` already produces) is parsed back into the segment array
  `Document#getIn` expects (`['trust', 'tool_allowlist', 0]`).
- **A lookup function, not inline computation during masking**:
  `maskConfig`/`maskTree` stay format-agnostic (always set `line: null`
  as the base shape) and get no new parameters; `discoverAgent` builds
  a `LineLookup` from the raw source text _after_ masking and maps over
  the resulting `secretFields` to fill in real values. Keeps
  `configParser.ts`'s two parses (plain-value masking vs. CST line
  lookup) decoupled — either can fail or be skipped independently
  without threading a lookup callback through the whole recursive
  `maskTree` walk.
- **JSON stays `null`, by design, not by oversight** (the plan's own
  definition of done): `JSON.parse` has no equivalent CST-with-positions
  in this codebase's chosen parser, and adding a second JSON parser
  just for source ranges wasn't judged worth it for a `Low` impact/`Med`
  effort item. `createLineLookup` returns an always-`null` lookup for
  `'json'` rather than a special case at each call site — one place
  encodes "JSON has no line info," not scattered null-checks.
- **Wired through `CHAP-SEC-001` and `CHAP-SEC-007`**, both of which
  already iterate `model.config.secretFields` per-field — the DoD only
  required `CHAP-SEC-001`-style findings, but `CHAP-SEC-007` costs
  nothing extra (identical shape, `field.line` already in scope) and is
  an honest, proportionate extension. Deliberately **not** wired into
  `CHAP-SEC-002`/`004` (a single finding represents the whole config
  file, not one field — no one line would be more "correct" than
  another) or sidecar secret files (`.env`/`secrets.yaml` via
  `CHAP-SEC-006`) — same mechanism could extend there later, but it's a
  distinct enough increment (a different discovery module,
  `sidecarSecrets.ts`) to defer rather than fold into this phase's
  scope silently.
- Console reporter's `formatLocation` already supported `file:line`
  formatting from the start (written once, exercised for the first time
  only now that a real line number exists) — no reporter changes needed
  anywhere; verified end-to-end via both the dev build and a real
  npm-pack install.

## Improvement plan, Phase 14 — Suppression config file (`.chaperonerc.json`)

- **`z.record(EnumSchema, ValueSchema)` vs. `z.partialRecord` (zod 4)**:
  discovered mid-implementation that `z.record` treats an enum key type
  as exhaustive — `z.record(SeveritySchema, z.number()).safeParse({high:
20})` fails with "expected number, received undefined" for every
  other severity, and `ZodRecord` has no `.partial()` method to relax
  it. `z.partialRecord(SeveritySchema, z.number())` is the correct zod-4
  API for a genuinely partial per-key mapping and is what
  `scoreWeights` uses; `severityOverrides` stays `z.record(z.string(),
SeveritySchema)` since its keys are arbitrary check IDs, not an enum.
- **Pipeline ordering — real reclassification before display filters,
  both before `--fail-on`/score**: `severityOverrides`/`ignore` are a
  conscious reclassification the user made (an accepted-risk decision),
  not cosmetics, so — unlike Phase 7's `--only-category`/
  `--skip-category`/`--min-severity`, which must never affect
  `--fail-on` — `applyChaperoneConfig`'s output feeds both the
  `--fail-on` decision and the posture score. The scan pipeline is now:
  raw findings → `applyChaperoneConfig` (severity overrides + active
  suppressions) → adjusted findings (what `--fail-on`/score use) →
  `applyDisplayFilters` (Phase 7's cosmetic-only filters) → what's
  actually rendered. `disabledChecks` sits one step earlier still —
  merged into `runChecks`'s own `skip` list, so those checks never
  produce findings at all rather than being suppressed after the fact.
- **Unknown check ID: warn in the config file, hard-fail on the CLI** —
  a deliberate, debatable split. `severityOverrides`/`ignore` entries
  referencing an unknown check ID print a warning and are otherwise
  ignored, matching the DoD's "warn, don't silently fail" precedent
  already set for expired suppressions (a stale suppression referencing
  a since-removed/renamed check shouldn't break a CI pipeline on a
  Chaperone version upgrade). `disabledChecks`, by contrast, is merged
  into the existing `--skip` mechanism and goes through the same
  unknown-ID validation `--skip`/`--only` already hard-error on — a
  direct CLI-adjacent check-ID list is more likely to be an immediate
  typo worth catching loudly than a config file surviving across
  upgrades.
- **`expires` (ISO date string) on an `ignore` entry**: once past, the
  entry stops suppressing — the finding reappears in output and feeds
  `--fail-on` again — and a warning is printed naming the check, the
  expiry date, and the original `reason` (when given), so a suppression
  can't silently outlive the justification it was added for. An
  unparseable `expires` value is treated as non-expiring rather than
  erroring — the field is optional and best-effort, not schema-enforced
  as a strict date.
- **`--config <file>` / `CHAPERONE_CONFIG` / default discovery**: an
  explicit path (flag or env var) must exist and validate or the scan
  hard-errors via `command.error()` (silently ignoring a typo'd path
  would be worse than failing loudly — consistent with how other
  explicit-path flags like `--output` behave on failure). With neither
  set, `./.chaperonerc.json` is looked up in the current working
  directory and its absence is treated as "no config," not an error.
  `LoadedConfig.path` (which file was actually loaded, if any) is
  computed but not currently surfaced to the user beyond the loaded
  config's effects — judged unnecessary for the DoD and left for a
  future `--verbose`-style addition rather than adding scope now.
- Tested all four config shapes end-to-end through the real CLI
  (`test/config/cli.chaperonerc.test.ts`): `severityOverrides` changing
  a finding's severity and therefore `--fail-on`, an active `ignore`
  suppression removing a finding, an expired `ignore` suppression
  _not_ removing the finding and printing a warning, `disabledChecks`
  preventing a check from running, `scoreWeights` changing the computed
  score across console/json/markdown output, both `--config` and
  `CHAPERONE_CONFIG`, and default-file auto-discovery. The
  unknown-check-ID-in-`disabledChecks` hard-error path was verified
  manually instead (same "would kill the vitest worker via
  `process.exit()`" caveat as every other `command.error()` path in
  this codebase — see cli.exitcode.test.ts/cli.options.test.ts).
  `chaperoneConfig.ts`'s pure functions (`loadChaperoneConfig`,
  `applyChaperoneConfig`) are also unit-tested directly
  (`test/config/chaperoneConfig.test.ts`).

## Improvement plan, Phase 15 — Baseline/diff mode

- **A saved JSON report is the baseline format, exactly as the plan
  anticipated** (`3.5`: "the schema already supports this for free") —
  `loadBaseline` (`src/config/baseline.ts`) validates against the same
  `ScanReportSchema` the JSON reporter already produces and enforces, so
  `chaperone scan --format json --output baseline.json` is the entire
  capture step. No separate baseline-specific format or schema.
- **Fingerprint excludes `location.line`, deliberately**: `checkId` +
  `location.filePath` + `location.detail` + `message` identifies "the
  same finding" across two scans. Line number was the obvious first
  candidate to include, but an edit anywhere above a finding in the same
  file shifts every later line number, which would make an untouched
  finding look "new" on the very next scan — the opposite of what a
  baseline is for. The remaining fields are specific enough that two
  genuinely different findings essentially never collide in practice.
- **`--baseline` is a real reclassification, not a display filter** —
  same category of decision as Phase 14's `severityOverrides`/`ignore`.
  The plan's own motivation ("without... disabling `--fail-on` entirely")
  only makes sense if the diffed-down set is what `--fail-on`/the
  posture score evaluate, not just what's printed. Pipeline order is now:
  raw findings → `applyChaperoneConfig` (Phase 14) → config-adjusted
  findings → `findNewFindings` (this phase, only when `--baseline` is
  passed) → the findings `--fail-on`/score/display-filters all see from
  here on. Applied _after_ Phase 14's config step, not before — a
  suppressed/reclassified finding shouldn't still count as "new" just
  because it wasn't in an older baseline.
- **No default-file auto-discovery for `--baseline`** (unlike
  `.chaperonerc.json`'s `./` lookup) — the plan only ever describes an
  explicit `--baseline <file>`, and unlike a missing suppression config
  (which just means "no suppressions," a safe default), a silently
  auto-picked-up _stale_ baseline is a much easier way to accidentally
  hide a real regression. An explicit path (flag or `CHAPERONE_BASELINE`
  env var, matching every other file-accepting flag's env-var
  convention) that doesn't exist or doesn't validate hard-fails via
  `command.error()`, consistent with `--config`/`--output`.
- Tested via the real CLI, per the DoD's own framing ("a saved report
  with a known subset of findings resolved/added"): current scan
  exactly matching the baseline reports nothing; a baseline missing one
  known finding reports exactly that finding as new and feeds
  `--fail-on`; a baseline containing every current finding does not fail
  the build even above `--fail-on`, despite real critical findings being
  present; a report saved via `--output` is accepted directly as a
  baseline. `findingFingerprint`/`findNewFindings`/`loadBaseline` are
  also unit-tested directly (`test/config/baseline.test.ts`), including
  the missing-file/invalid-JSON/invalid-schema error paths. The
  missing/invalid-`--baseline`-file hard-error path itself was verified
  manually (same `command.error()`/`process.exit()` constraint as every
  other such path in this suite).

## Improvement plan, Phase 16 — Non-JS skill support (first cut)

- **Regex-over-raw-text, deliberately, not a ported AST approach** —
  matching the plan's own framing (`1.9`: "same fragility as the
  pre-Phase-10 JS approach"). `src/discovery/pythonCapabilities.ts`
  mirrors the exact pre-Phase-10 `skillsScanner.ts` shape (an array of
  `RegExp`s per capability, `Array.some`/`Array.filter`), not
  `astCapabilities.ts`'s import/binding-resolution machinery — adding a
  Python parser/tokenizer dependency is a much bigger bet than a "first
  cut" warrants, and there's no such dependency in this project today.
- **Dispatched per-file by extension** (`detectCapabilitiesForFile` in
  `skillsScanner.ts`), not per-skill on concatenated source: JS/TS files
  still go through the real AST path, `.py` files go through the new
  regex path, and both funnel into the same `mergeCapabilities` —
  keeping one merge step rather than a language-specific aggregation
  branch. `SOURCE_EXTENSIONS` (now `JS_TS_SOURCE_EXTENSIONS ∪
PYTHON_SOURCE_EXTENSIONS`) is the "SOURCE_EXTENSIONS-equivalent
  broadened" the DoD asks for.
- **Field-by-field mapping to Python's own idioms, not a literal
  transliteration**: `eval()`/`Function()` (JS) maps to `eval()`/
  `exec()`/`__import__()` (Python) — all three are Python's
  dynamic-code/dynamic-import primitives, the same semantic category
  `dynamicEval` represents for JS. `fileSystemScoped`'s proxy signal
  (`path.join(__dirname, ...)` for JS) maps to
  `os.path.join(os.path.dirname(__file__), ...)` for Python — same
  "is file access scoped to a fixed base directory" question, expressed
  in each language's own idiom for "next to this file".
- **`dataFlowToShellExec` is always `false` for Python, on purpose** —
  Phase 16's scope is capability _detection_, not porting CHAP-INJ-002's
  bounded intra-file taint trace (Phase 10) to a second language. A
  Python skill can still trip CHAP-INJ-002 at its lower (`medium`,
  unconfirmed-shape-match) severity via `shellExec` +
  `networkAccess`/`fileSystemAccess`; it just never reaches that check's
  `high` (confirmed-data-flow) tier the way a JS skill can.
- **Caught a real regex bug while building the clean fixture**: the
  initial `open\([^)]*,\s*['"]a?[wx]b?['"]/` pattern for a write-mode
  `open()` call stops at the _first_ `)` — a nested call in the path
  argument (`open(os.path.join(WORKSPACE, name), "w")`, the natural way
  to write a scoped-workspace path in Python) defeats it entirely, since
  `os.path.join(...)`'s own closing paren is reached before the mode
  string. Fixed by bounding the pattern to one line (`[^\n]*` instead of
  `[^)]*`) rather than requiring no intervening parens — regression-
  tested directly (`test/discovery/pythonCapabilities.test.ts`).
- **New fixture skills, not just unit tests** — `py-cache-cleaner`
  (vulnerable-agent: `subprocess.run(...)` + a destructive `-delete`
  argument, no manifest `confirmationRequired`) and `py-notes`
  (clean-agent: `open(..., "w")` scoped to
  `os.path.dirname(__file__)`-relative `workspace/`) prove the new path
  end-to-end through `discoverAgent`, not just against
  `detectPythonCapabilities` directly — real existing checks
  (`CHAP-AGY-001`, `CHAP-AGY-003`, `CHAP-SUP-001/002/003`) now produce
  findings against Python source with zero check-level changes, since
  every check reads `skill.capabilities`, never the source language.
  `test/scan/fullCatalog.test.ts` and every affected
  check/discovery test were updated against real captured CLI output
  (44 → 49 vulnerable-agent findings; 3 → 4 clean-agent `CHAP-SUP-003`
  findings), never hand-computed.

## Improvement plan, Phase 17 — Real agent framework adapter (`--profile`)

- **Scoped to a right-sized MVP, not the open-ended "strategic bet"
  framing the plan flags this phase with.** `3.1`/Phase 17 is explicitly
  marked in the plan as needing "its own dedicated planning pass" and
  listed only as a placeholder with its scope. Rather than either
  skipping it or over-building (a second full check registry, a plugin-
  style profile-loading system — Phase 21's actual job), this lands the
  literal DoD: `chaperone scan --profile <real-target> <path>` against a
  real (not synthetic) config shape, with its own fixture pair, at
  minimum blast radius on the existing architecture.
- **MCP server config chosen as the real target** (the plan's other
  named option, "Open Interpreter", is a less standardized/stable
  format) — a genuine, stable, widely-used shape:
  `.mcp.json`/`mcp.json`/`claude_desktop_config.json`, a top-level
  `{"mcpServers": {"<name>": {command/args/env | url/headers}}}`
  object, used by Claude Desktop, Claude Code, and other MCP clients.
- **Mapped onto the existing `AgentModel`/29-check catalog, not a
  parallel one** — `src/discovery/mcpProfile.ts`'s `discoverMcpAgent`
  produces the exact same `AgentModel` shape `discoverAgent` already
  does, so every existing check runs against it unmodified. Deliberately
  honest about which checks that means "produces meaningful findings"
  for: only `CHAP-SEC-001` (a server's `env` block reuses
  `configParser.ts`'s `maskConfig` verbatim — it walks any JSON tree for
  secret-shaped keys, an MCP server's `env` is just more tree to it),
  `CHAP-SEC-003` (the config file's own permission fact, same
  `getFilePermissionFact` machinery), and `CHAP-SUP-001` (a new
  `detectPinnedRef` heuristic: an `args` entry naming an exact
  `@<semver>` is pinned, a bare package name or `@latest` isn't — the
  same question `extractProvenance`'s regex asks for the default
  profile, expressed in MCP's own idiom). Every skill's `capabilities`
  are left all-`false` (there's no source code to statically analyze —
  an MCP server is an external process/endpoint) and
  `dependencies.manifestPath` is left `null` (no separate npm-manifest/
  lockfile concept exists for an MCP server entry) so
  `CHAP-AGY-*`/`CHAP-INJ-002`/`CHAP-SUP-002/003/005/006` correctly stay
  silent rather than being forced onto a shape they don't fit.
  `CHAP-OBS-001`/`CHAP-OBS-003` (absence-based: no logging configured,
  no kill-switch file at the target root) fire regardless of profile —
  a real, if incidental, signal for MCP installs too.
- **`emptyModel` extracted and shared, not duplicated** — the
  "everything absent" `AgentModel` builder (previously a private
  function in `discovery/index.ts`) is now exported and reused by both
  the "no default install found" path and the new "no MCP config found"
  path, rather than a second near-identical copy in `mcpProfile.ts`.
  `DiscoveryOptions`/`DiscoveryResult` stay the single shared contract
  both profiles implement — `index.ts` imports `discoverMcpAgent` (a
  value) from `mcpProfile.ts`, which imports those two types (type-only,
  erased at compile time) back from `index.ts`; safe because neither
  side calls the other at module-top-level, only inside a function body
  invoked later.
- **MCP configs are project-scoped by convention, not home-scoped** —
  unlike the default profile's `DEFAULT_ROOTS` probe under `$HOME`, the
  `mcp` profile's "no explicit path" default is `process.cwd()` (an
  `.mcp.json` is conventionally checked in alongside a repo, the same
  way `tsc`/`eslint` default to the current directory). The `[path]`
  CLI argument's meaning stays identical across profiles either way — a
  directory to look in, never a config file path directly.
- **`pinnedRef: null` (not `false`) for a remote/URL-based server** — a
  server with no `command`/`args` has no package/version concept to be
  pinned or not, so `CHAP-SUP-001`'s existing null-vs-false branch
  ("unpinned" vs. "no version/ref info found") already renders this
  honestly with zero changes to that check.
- Tested at three layers: `test/discovery/mcpProfile.test.ts` (the pure
  discovery function — file-name variants, missing/malformed config,
  secret extraction, all three `pinnedRef` cases, permission facts,
  cwd-default resolution, a malformed `mcpServers` entry, and
  confirmation the default profile is byte-for-byte unaffected),
  `test/scan/mcpProfileFullCatalog.test.ts` (the new fixture pair run
  through the real, unmodified `ALL_CHECKS` catalog — a fullCatalog.
  test.ts-style exact-count assertion, proving the "meaningful findings"
  DoD end-to-end), and `test/cli.profile.test.ts` (`--profile`/
  `CHAPERONE_PROFILE` through the real CLI). The invalid-`--profile`-
  value hard-error path was verified manually (same `command.error()`/
  `process.exit()` constraint as every other such path in this suite).

## Improvement plan, Phase 18 — Offline vulnerability database

- **A curated snapshot, not the whole OSV database, and genuinely fetched,
  not hand-typed** — `1.15`'s "real-fix half" calls for a "bundle/refresh
  an offline OSV or npm-advisory snapshot", not a live-equivalent
  replacement. `scripts/refreshVulnDb.ts` queries OSV.dev's real API
  (`https://api.osv.dev/v1/query`) for a small, explicit list of
  well-known npm packages (`lodash`, `minimist`) and writes the result to
  `src/checks/shared/vulnDb.ts` — genuinely fetched data (this script was
  actually run against the live API while building this phase, not
  synthesized), not a plausible-looking approximation. Adding a package
  means editing one array and re-running the script.
- **Out-of-band means genuinely out-of-band**: the refresh script is
  never invoked by `scan`, `test`, `build`, or CI — `npm run refresh:vulndb`
  is the only way it runs, and it's the one deliberate place in this
  whole codebase that makes an outbound network call. Verified by
  `test/scan/noNetworkCalls.test.ts`, which spies on every network
  primitive Node exposes (`fetch`, `http.request`/`.get`,
  `https.request`/`.get`) with a throwing implementation and runs a real
  `chaperone scan` through it — not scoped to just `CHAP-SUP-003`, since
  a future check regressing this guarantee should fail the same test.
- **A deliberately simple, static version match — documented, not
  hidden** (`semver.ts`): no `semver` dependency (matches this project's
  existing small-dependency-footprint philosophy — same reasoning as
  Levenshtein distance being hand-rolled rather than pulled in). Since
  this is a static, config-only scan with no lockfile parsing and no
  node_modules inspection, the actual _resolved_ version a real install
  would use is never available — `extractBaseVersion` takes the first
  X.Y.Z-shaped token in the raw package.json specifier as a stand-in. A
  specifier with no such token (`"latest"`, `"*"`, a git URL, a
  workspace reference) is skipped, never guessed at. This is a real,
  acknowledged limitation (a caret range's actual resolution could land
  on a patched version even when its declared floor looks vulnerable, or
  vice versa) — but a materially stronger, more honest signal than the
  check's previous "fires on any manifest, always" behavior.
- **`SkillDependencyInfo` gained `versionsByName`** (name -> raw
  specifier string), alongside the existing `names` (which only fed
  CHAP-SUP-006's typosquat check and discarded version info entirely).
  `skillsScanner.ts`'s `extractDependencyNames` became
  `extractDependencies`, returning both from one manifest read instead
  of two. `mcpProfile.ts` (Phase 17) gained the same field, empty — no
  npm-manifest concept exists for an MCP server entry, so CHAP-SUP-003
  correctly finds nothing to match there, same reasoning already
  documented for CHAP-SUP-002/006 in that phase's entry.
- **Severity restored to `high`** (from the `info`-severity
  `severityNote: 'Info (demoted from High)'` the DoD's Phase 15/1.15
  mitigation half introduced) — the plan's own instruction, now that the
  signal is a genuine version match rather than "any manifest exists".
  `severityNote` itself (the mechanism, not this specific use) stays in
  `engine/types.ts`'s `Check` interface for a future check that needs
  it; its two tests (`cli.options.test.ts`,
  `generateChecksDoc.test.ts`) were rewritten against a synthetic
  `Check` object instead of `CHAP-SUP-003` specifically, so they keep
  testing the mechanism rather than becoming permanently coupled to
  whichever real check happens to use the feature.
- **One finding per (skill, vulnerable dependency), aggregating every
  matching advisory into a single message** — not one finding per
  advisory. `plugin-loader`'s `lodash@^4.17.15` matches 6 separate GHSA
  entries in the snapshot; emitting 6 nearly-identical findings for one
  dependency would be noisy without being more actionable, and every
  other check in this codebase already reports one finding per
  skill/condition rather than per sub-detail (e.g. CHAP-AGY-003 lists
  every destructive keyword in one finding's message, not one finding
  per keyword). The finding's severity is the _worst_ matching
  advisory's; its message names every matching ID so nothing is hidden,
  just consolidated.
- **Fixture changes, real end-to-end proof**: `plugin-loader`
  (vulnerable-agent) gained `"lodash": "^4.17.15"` (matches 6 real
  advisories); `weather` (clean-agent) gained `"lodash": "^4.18.2"` (a
  genuinely patched version, above every tracked advisory's `fixed`
  bound) — a real true-negative against real data, restoring the DoD's
  literal ask ("CHAP-SUP-003 produces true-negative results on the clean
  fixture again"), not just "no manifest present". `fullCatalog.test.ts`
  and every other affected test were updated against real captured CLI
  output (49 → 44 vulnerable-agent findings, since 6 old `info` findings
  became 1 `high` finding; clean-agent goes from `{CHAP-SUP-003: 4}` to
  `{}` — a genuinely empty, fully clean scan for the first time).

## Improvement plan, Phase 19 — HTML reporter

- **Zero JavaScript, by design, not just "no CDN"** — `3.10` asks for
  "no external JS/CSS dependency"; taken to its logical conclusion, the
  HTML reporter ships no `<script>` tag at all, inline or otherwise. A
  static document with zero JS has nothing that could ever produce a
  runtime console error in the first place, which is the strongest
  possible way to satisfy the DoD's "opens correctly... with no console
  errors" — verified structurally in tests (no `<script`, no `on*=`
  inline handler) rather than by launching a real browser (none
  available in this environment).
- **No external resource of any kind** — no CDN link, no separate
  `.css` file, no web font, no image. One inline `<style>` block, same
  "single self-contained file" spirit as every other reporter (JSON/
  SARIF/Markdown/GHA all already produce one string with no side files).
- **Reuses the exact same score/grouping logic as every other
  reporter** (`computeScore`, `compareSeverity`, the same severity-group
  ordering) — no new business logic, purely a new presentation layer.
  `scoreWeights` threading works identically to console/json/markdown.
- **All interpolated content is HTML-escaped** (`escapeHtml`) — a
  finding's `message`/`location`/`remediation` text is Chaperone's own
  generated prose (never raw file content; secrets are already masked
  upstream — see `configParser.ts`), but a scanned skill/file name
  could still legitimately contain `<`/`>`/`&`/quotes, and this is
  output meant to be opened in a real browser, unlike the other
  reporters' more structured formats.
- Tested at three levels, matching the DoD's own wording ("tested
  against both fixtures; opens correctly as a static file"):
  `test/reporters/html.test.ts` (structural well-formedness — balanced
  tags, no script/external resources, escaping, score-weight
  application), `test/cli.exitcode.test.ts` (`--format html` against
  both fixtures via the real CLI), and a dedicated `--output
report.html` test that writes a real file to disk and reads it back,
  the literal "opens correctly as a static file" scenario.

## Improvement plan, Phase 20 — Multi-root & Docker-aware scanning

- **`--all`: a right-sized `/*` matcher, not a general glob engine** —
  `3.2`'s own example (`~/agents/*`) is the one shape this needs to
  handle well: "every immediate subdirectory of a parent directory". No
  new dependency (`glob`/`fast-glob`), no `**`/character-class support —
  a pattern with no trailing `/*` degenerates to a single literal
  directory. Documented explicitly that the shell would normally expand
  `~/agents/*` before Chaperone ever sees it, so the flag only does
  anything useful when quoted (`--all '~/agents/*'`) — the same
  quoting convention tools with their own glob semantics already use.
- **One aggregate report, not N separate files** — the DoD's own two
  named alternatives; picked the simpler, more uniformly-testable one.
  `renderMultiTargetReport` (reporters/index.ts) degenerates
  byte-for-byte to `renderReport`'s own single-target output for the
  overwhelming majority case (no `--all`/`--docker`), so this refactor
  changed zero observable behavior for every existing caller — verified
  by the full 560-test suite passing unchanged except one test whose
  _mock target_ moved (see below). `json` aggregates as an array of the
  same schema-valid report objects; `sarif` merges into one real
  multi-run SARIF document (SARIF's own native way to represent more
  than one analysis pass — naively concatenating N SARIF documents isn't
  valid JSON); every other format is header-separated concatenation,
  since it's human-facing prose/line-based output already.
- **`cli.ts`'s scan action factored into `scanOneTarget` +
  target-resolution + aggregation** — the single biggest structural
  change in this phase. `scanOneTarget` is the exact same discover ->
  check -> config/baseline-adjust -> display-filter pipeline that used
  to be inlined once in the action body, now callable once per target.
  Caught one real test-design coupling while doing this:
  `cli.unexpectedError.test.ts` simulated "an unexpected error deep in
  the pipeline" by mocking `renderReport` directly — since the action
  now always calls `renderMultiTargetReport` (which only calls
  `renderReport` via its own internal, un-mocked module binding — the
  classic `vi.mock` gotcha where a mocked export doesn't intercept an
  in-module call to the same function), the mock target had to move to
  `renderMultiTargetReport`. A legitimate test update reflecting where
  the real integration point moved, not a workaround.
- **`--docker` via `docker cp`, not `docker exec`** — reads a
  container's filesystem directly from its image/writable layers, so it
  works on a _stopped_ container and never depends on a shell (or any
  binary at all) existing inside it, unlike `docker exec sh -c '...'`
  which needs both. One subprocess call, argv-array invocation only
  (`execFileSync`, never a shell string — no injection surface from a
  container name/path), a 30s timeout so a hung daemon can never hang
  `chaperone scan` indefinitely, and the extracted content lands in a
  throwaway local temp directory that the _existing, already-tested_
  local-filesystem discovery pipeline reads completely unmodified — no
  fs call anywhere in `discovery/` needs to know or care its source was
  ever a container.
- **A deliberate, considered exception to "no subprocess"** — Phase 12
  (`1.13`) explicitly declined to shell out to `git` for a _simpler_
  case (gitignore semantics), citing exactly this class of risk: a new
  binary-on-PATH dependency, cross-version behavioral differences, and a
  categorically different failure mode (a hung/misbehaving subprocess)
  than a plain file read has. `--docker` is the first time this
  reasoning is overridden — justified because the entire feature is
  meaningless without it (there is no way to read a container's
  filesystem from the host other than asking the Docker daemon), and
  scoped as tightly as that Phase 12 entry's own concerns allow: opt-in
  only (never triggered without the explicit flag), one call, a hard
  timeout, and the real daemon error surfaced verbatim (via
  `execFileSync`'s captured stderr) rather than a generic failure
  message.
- **The env-var-injection subtlety `3.3` itself calls out is
  deliberately NOT solved here** — a containerized secret set via
  `docker-compose.yml`'s `environment:`/`env_file:` sits one layer
  removed from both the agent's config _and_ Chaperone's own process
  environment, meaning `CHAP-SEC-007` (env-var-actually-set check)
  can't see it through `--docker` any better than it already can't for
  a local install with the same pattern. The plan's own text frames
  this as "worth designing around deliberately", not a Phase-20
  requirement — noted, deferred, not silently dropped.
- **Real-container testing, not mocked** — Docker was confirmed
  available in this session (daemon running), and GitHub Actions'
  `ubuntu-latest` runners ship Docker pre-installed with the daemon
  running by default, satisfying the DoD's own "(if feasible in CI)"
  hedge on both counts. `test/discovery/dockerSource.test.ts` and
  `test/cli.docker.test.ts` spin up a real throwaway `busybox` container,
  populate it via `docker cp` from the host, and verify extraction/
  scanning/cleanup against it — `describe.skipIf(!dockerAvailable)`
  makes the suite degrade gracefully (skip, not fail) on a machine
  without Docker rather than hard-requiring it everywhere.
- Also tested: `expandAllPattern` directly (trailing-`/*` expansion,
  sorting, empty-parent, missing-parent error, `~` expansion, no-`/*`
  degeneration), `renderMultiTargetReport` directly (single-target
  byte-identity with `renderReport`, json/sarif aggregation shape,
  header-separated concatenation, the zero-targets edge case), and
  `--all`/`--docker` through the real CLI against real temp-dir/
  container fixtures. `--all` matching zero directories and an unknown
  `--docker` container both go through `command.error()`/
  `process.exit()` and were verified manually, same convention as every
  other such path in this suite.

## Improvement plan, Phase 21 — Plugin system for custom checks

- **Synchronous `require()` (via `createRequire`), not a dynamic
  `import()`** — the single biggest design decision in this phase, and
  a real architectural constraint, not a stylistic preference. `run()`
  (`cli.ts`) calls commander's synchronous `.parse()`, not
  `.parseAsync()`, and the scan action is itself synchronous; converting
  either to async to support `import()` would mean every one of the
  580+ existing tests calling `run(...)` synchronously and immediately
  asserting on its result would need to become `await run(...)` — a
  huge, high-risk mechanical change for a feature whose DoD only asks
  for "a sample external check module loads and runs correctly". Node's
  `require()` (even via `createRequire` from an ESM module) loads
  CommonJS synchronously and reliably on every Node ≥20 patch version;
  `chaperone scan` stays exactly as synchronous as it already was.
- **The tradeoff, stated plainly**: a plugin module must be loadable as
  CommonJS — a `.cjs` file (works regardless of context) or a `.js` file
  in a directory whose nearest `package.json` says `"type": "commonjs"`
  or has no `type` field at all. A genuine ESM-only plugin isn't
  supported in this v1. A real, documented limitation, not silently
  dropped — most plugin authors writing a small, focused check module
  have no reason to need ESM-only syntax (top-level await, etc.) for
  this purpose anyway.
- **The trust boundary is stated as plainly as the plan itself asks
  for** (`3.13`: "documented as an explicit trust boundary... rather
  than left implicit") — not just in a doc file nobody reads: loading
  any plugin prints an unmissable warning to stderr naming exactly which
  path(s) were loaded and repeating the "no sandboxing" warning every
  single scan, never just once. `pluginLoader.ts`'s own doc comment,
  the README's dedicated Plugins section, and a new numbered item in
  Security & ethics all say the same thing in different words: a plugin
  is arbitrary code with full `AgentModel` access, loading one is your
  trust decision, not Chaperone's own read-only/no-network guarantees
  extending to it.
- **A `Check`-shaped default export (object or array), validated at
  load time** — mirrors `ALL_CHECKS`'s own shape (`Check[]`) so nothing
  about a plugin author's mental model differs from reading the
  built-in checks' source for reference. Validated with the same zod
  schema style already used throughout this codebase (`SeveritySchema`/
  `CheckCategorySchema` reused directly) for every field except `run`
  (a function, checked by `typeof`, not zod). An invalid shape, a
  missing field, or a plugin path that fails to load at all is a hard
  load error (`command.error()`), not a silently-skipped plugin — a
  plugin the user explicitly asked for failing is worth stopping the
  scan over, the same reasoning `--config`/`--baseline` already apply
  to their own explicit-path failures.
- **A check-ID collision (with a built-in check, or between two
  plugins) is a hard error, never a silent override** — `mergeChecks`
  rejects it outright. A plugin silently shadowing `CHAP-SEC-001`
  (say) would be a uniquely confusing way to lose a real finding with
  no visible sign anything was wrong.
- **`--plugin`/`.chaperonerc.json`'s `plugins` merge, config-file
  entries first** — same "config file as the base, CLI flags layered
  on top" convention `disabledChecks`→`--skip` already established in
  Phase 14. `chaperone checks`/`chaperone explain` deliberately do NOT
  load plugins (v1 scope: plugin checks are scan-only, not listed
  alongside built-ins in the catalog or explainable by ID) — a
  reasonable, documented scope boundary distinct from the DoD's actual
  ask.
- Tested at three levels: `test/engine/pluginLoader.test.ts`
  (`loadPlugin`/`loadPlugins`/`mergeChecks` directly — the real sample
  plugin actually running and producing a finding, array-of-checks
  exports, every error path), `test/cli.plugin.test.ts` (`--plugin`
  through the real CLI: repeatable flags, `.chaperonerc.json`'s
  `plugins` array, the stderr trust-boundary warning, feeding
  `--fail-on`), and manual verification against the real packaged
  (`npm pack`) binary. `test/fixtures/plugins/` holds three fixtures:
  a real working sample (`samplePlugin.cjs`, referenced from the
  README's own example), a structurally invalid one, and one that
  deliberately collides with a real built-in check ID. The
  invalid-plugin/collision/missing-plugin-path errors all go through
  `command.error()`/`process.exit()` and were verified manually, same
  convention as every other such path in this suite.

## Improvement plan, Phase 22 — Guided remediation (`chaperone fix`)

- **A separate top-level command, not a `scan` flag** — the plan's own
  instruction, taken literally: "kept architecturally and namewise
  distinct from `scan`'s read-only guardrail... named/packaged
  distinctly enough that 'Chaperone found this' and 'Chaperone changed
  this' are never confusable." `chaperone scan` has zero write
  capability, period, regardless of any flag — `fix` is the one place
  in this entire codebase that writes to the target install, and only
  under its own separate gate.
- **`--write` requires `--dry-run` to also be passed, in the same
  invocation** — the DoD's exact wording ("nothing is written unless
  the user re-runs with `--write` after reviewing it") reads as two
  separate invocations, but a cross-invocation "did they actually review
  it last time" gate would need persistent state and is trivially
  defeatable (nothing stops someone from running `--dry-run` against a
  different check, or years ago, or on a different machine, and treating
  that as "reviewed"). Requiring both flags **together** is a strictly
  stronger, mechanically enforced guarantee: the proposed change is
  _always_ printed immediately before the write happens, in that exact
  order, every single time, with no way to separate the two steps even
  accidentally. `--write` alone unconditionally refuses, every time,
  telling the user exactly what to run instead.
- **The "diff" is a masked, field-level change list, not a raw
  unified/line diff of file text** — a real unified diff of the file's
  "before" content would show the actual literal secret on the removed
  line, directly contradicting the "secrets are masked in all output"
  guarantee this project holds everywhere else. `renderFixPlan` prints
  `keyPath: <masked-old-value> -> <new-value>` instead, reusing the
  exact same `displayValue` the finding itself already computed (see
  `configParser.ts`'s `maskConfig`) — the fixer never needs to know or
  re-derive the real old value at all, only the field's _location_
  (`keyPath`), to overwrite it.
- **Only `CHAP-SEC-001` has a working fixer** — the DoD's own floor
  ("at least one check"), not parity with the 29-check catalog; `3.14`
  itself is framed as "explicitly out of scope for v1... if ever built".
  `src/fix/index.ts`'s `FIXERS` registry is the obvious place to add
  another later. The chosen fix (replace a literal secret with a
  `${SUGGESTED_ENV_VAR_NAME}` reference) is the single most common,
  least risky, most mechanically obvious remediation in the whole check
  catalog — a config-file edit with one unambiguous right answer, unlike
  e.g. "fix an unrestricted shell-exec skill" (no single correct code
  change exists).
- **YAML edits preserve formatting/comments via `YAML.Document#setIn`**
  (a round-trip-preserving edit, the same API family `configParser.ts`'s
  line-lookup already uses `YAML.parseDocument` for), not a naive
  parse-and-regenerate-from-scratch — a config file's comments and key
  order matter to the person who wrote it, and a "fix" that silently
  reformats the whole file around one line would be a worse experience
  than the bug it's fixing. JSON has no comments to preserve, so a plain
  `JSON.parse`/`setInPlainObject`/`stringify` round-trip is fine there —
  same reasoning `maskConfig` already applies for JSON.
- **The suggested env-var name uses the full dotted keyPath, not just
  the leaf key** (`channels.telegram.bot_token` ->
  `CHANNELS_TELEGRAM_BOT_TOKEN`, not `BOT_TOKEN`) — two different
  channels' bot tokens (`telegram`/`discord`) would otherwise collide on
  the same suggested variable name.
- **`fix` is single-target only** — no `--all`/`--docker`/`--profile`
  support. Batch remediation across many installs at once is a much
  higher-blast-radius operation than batch _scanning_, and nothing in
  the DoD asks for it; a deliberate, documented scope boundary, not an
  oversight, consistent with keeping this phase's new write capability
  as narrow and easy to reason about as possible.
- Tested at three levels: `test/fix/envVarName.test.ts` and
  `test/fix/chapSec001Fixer.test.ts` (the fixer's `plan()` directly —
  YAML formatting/comment preservation, JSON support, the null cases,
  multiple distinct env-var names, and confirming `plan()` itself never
  writes anything), `test/cli.fix.test.ts` (through the real CLI: the
  default/`--dry-run` no-write behavior, `--dry-run --write` together
  actually writing and in the right order, the "nothing to fix" message,
  and — critically — a dedicated regression test that `chaperone scan`
  itself still never modifies a file even when fixable findings are
  present), and manual verification against the real packaged
  (`npm pack`) binary, including confirming a fixed config file no
  longer trips `CHAP-SEC-001` on a subsequent `scan`. `--write` without
  `--dry-run`, an unknown check ID, and an unresolved target all go
  through `command.error()`/`process.exit()` and were verified manually,
  same convention as every other such path in this suite.

## Improvement plan, Phase 23 (5.1) — Golden-file/snapshot reporter tests

- **Vitest's built-in `.toMatchSnapshot()`, no new dependency** —
  already bundled with the test runner this project uses; no separate
  snapshot library (`jest-snapshot` standalone, etc.) needed.
- **Two normalizations are load-bearing, not optional** — a scan
  timestamp and the target's absolute path both vary between runs (a
  fresh `mkdtempSync` temp dir every time) and between machines/CI
  (different filesystem root entirely). Without normalizing both before
  snapshotting, every single run would look like a "changed" snapshot,
  making the whole mechanism useless. The timestamp is supplied as a
  fixed literal in the constructed `ScanMetadata` (simpler than
  regex-stripping a real one); the temp directory's exact path is known
  at test time (`copyFixtureWithPermissions`'s own return value) and
  replaced verbatim with a fixed placeholder.
- **Real fixtures, real discovery, real checks — not hand-built
  `Finding[]` arrays** (unlike every `test/reporters/*.test.ts` file,
  which intentionally stays scoped to one reporter's own formatting
  logic against a small synthetic input). This test exists specifically
  to catch a regression somewhere in the full
  `discoverAgent` -> `runChecks` -> `renderReport` pipeline that a
  narrower, mocked-input reporter test wouldn't see. Reuses the same
  chmod'd-copy-of-a-real-fixture technique `fullCatalog.test.ts`
  established (git doesn't preserve exact file modes, so `CHAP-SEC-003`
  needs an explicit, portable one) rather than inventing a new pattern.
- **Verified the test is not vacuous**: deliberately introduced a real
  one-word regression into `console.ts`'s report header, confirmed the
  snapshot test failed and printed a clear diff naming exactly what
  changed, then reverted — before trusting this as a real signal, not
  just as passing tests.
- All six report formats (`console`/`json`/`sarif`/`markdown`/`gha`/
  `html`), both fixtures — 12 snapshots total, committed alongside the
  test in `test/scan/__snapshots__/`.
- **CI itself caught a real environment-dependent leak in the first PR
  for this sub-item**, on the very mechanism designed to prevent it:
  `CHAP-SUP-004`'s finding location is a relative-looking
  `"package.json#scripts.<name>"` string (unlike every other check,
  whose location is already an absolute path). `formatSarifReport`'s
  `pathToFileURL()` resolves that relative string against the _test
  process's own_ `process.cwd()`, not against the fixture's copied
  temp directory — so the SARIF snapshot embedded a `file://` URI
  rooted at wherever the repo happened to be checked out, which
  differs between a local machine and a GitHub Actions runner exactly
  as much as a temp directory path does. Passed locally, failed on
  push. Fixed by normalizing `pathToFileURL(process.cwd()).href` the
  same way the temp directory itself is normalized — a real example of
  exactly the class of accidental-environment-dependence bug this
  whole sub-item exists to catch, just one turn removed (in the test's
  own normalization logic, not in application behavior).

## Improvement plan, Phase 23 (5.2) — Property-based/fuzz testing (fast-check)

- **`fast-check`, pinned exact** (matching every other devDependency's
  pinning convention in this project — no caret range, even though `npm
install --save-dev` defaults to one) — the standard TS property-based
  testing library, exactly as the plan itself names it.
- **Two real bugs found and fixed during development, not hypothetical
  ones** — this sub-item's whole reason to exist, demonstrated
  immediately:
  1. `isGitignored('', [...])` (and separately, `isGitignored('.',
[...])`) threw a raw, uncaught `TypeError`/`RangeError` from the
     underlying `ignore` package's `.ignores()`, rather than returning
     a boolean like the function's own contract promises. Fixed by
     wrapping the match call in a `try`/`catch`, treating **any**
     exception the underlying library throws the same safe way an
     empty `gitignoreFiles` list already is: not ignored. Deliberately
     a broad catch, not a narrow "handle empty string" special case —
     shrinking kept finding _more_ rejected input shapes (`.` was the
     second one found immediately after fixing the first), and there
     was no principled way to enumerate every string `ignore` considers
     "not a valid `path.relative()`'d string" up front. No real caller
     in this codebase can currently produce one of these degenerate
     path strings — every real relative path comes from an actual
     discovered file — but the function's own boundary should never
     surprise a caller with a library-internal exception type
     regardless.
  2. A flawed _test_ assumption, not an application bug: a
     `JSON.stringify(value) -> parseConfigSource(json)` "round-trips
     the original value" property failed on `-0` (`fc.jsonValue()` can
     generate it), because `JSON.stringify(-0) === '0'` — JSON itself
     has no negative-zero representation, so this was never something
     `parseConfigSource` did wrong. Fixed the property itself: compare
     against `JSON.parse(source)` (the same source string, run through
     the same lossy JSON round-trip on both sides), not the original
     fast-check-generated value — the actually-correct invariant being
     "behaves identically to a plain `JSON.parse`", not "is a perfect
     round trip of arbitrary JS values through a format that can't
     represent all of them".
  3. Also observed, not a bug: the YAML fuzz property surfaced genuinely
     obscure input the hand-picked test cases never exercised (a bare
     `%` directive line, an unresolved `!P` tag) — `YAML.parse` handles
     both by printing a `console.warn`-level warning and continuing
     (never throwing), so the "only ever throws a real `Error`"
     property held throughout; kept as evidence fuzzing is exploring
     real edge cases, not just passing trivially.
- **The real security property, not just "doesn't throw"**: for
  `maskConfig`, the most valuable property fuzzed is that a secret-
  shaped field's literal value never appears anywhere in the masked
  output, for randomly generated secret-shaped keys and long
  (non-env-reference-looking) values — a genuine invariant this
  project's whole "secrets are masked in all output" guarantee rests
  on, exercised far beyond the specific example values the hand-picked
  tests use.
- **Positive (recall) and negative (precision) properties for
  `isGitignored`**, not just "doesn't crash": a bare filename listed
  verbatim in the root `.gitignore` is always ignored; a different,
  unlisted name never is; a nested `.gitignore`'s bare pattern matches
  within its own directory but never leaks to an unrelated root-level
  file of the same name (`scopePattern`'s entire reason to exist,
  improvement_plan.md 1.14) — fuzzed across a wide generated name space,
  not just the specific examples the existing example-based test suite
  already covers.

## Improvement plan, Phase 23 (5.3) — Performance/scale test fixture

- **Generated at test time, not committed to git** — a 500-skill
  synthetic install (1,000+ files) has no business bloating the repo's
  history the way a real fixture pair does; `buildLargeSyntheticInstall`
  builds it fresh into a temp directory on every test run and cleans up
  afterward, the same `mkdtempSync`/`afterEach` pattern every other
  temp-dir-based test in this suite already uses.
- **A concrete wall-clock ceiling, not a micro-benchmark** — no
  statistical rigor, no baseline-comparison harness, no `tinybench`-
  style dependency. A single generous budget (15s, run through
  `discoverAgent` + the full `runChecks(model, ALL_CHECKS)`) that a real
  algorithmic regression (an accidental O(n²) somewhere in discovery or
  the check engine) would blow through loudly, while staying far enough
  above ordinary CI noise/variance to never be flaky. A real run on a
  normal development machine currently completes the full 500-skill
  scan in well under 100ms — the 15s ceiling has enormous headroom
  specifically so this test's value is "catches a real regression",
  not "asserts today's exact performance number".
- **Verifies checks actually ran across the whole set, not just that
  discovery finished** — every synthetic skill is built to trip
  `CHAP-AGY-004` (a `fetch()` call with no `domainAllowlist`
  declared), and the test asserts exactly `SKILL_COUNT` such findings —
  a cheap correctness sanity check riding along with the timing
  assertion, catching a scenario where discovery silently truncated the
  skill list (which would otherwise make the test pass _faster_, for
  the wrong reason).
- **A second, smaller case for "deep source trees"** (the plan's other
  named scenario) — one skill nested 20 directories deep, confirming
  `skillsScanner.ts`'s existing `MAX_SCAN_DEPTH` bound (already in place
  before this phase, for an unrelated reason — bounding recursive
  directory listing) also keeps a pathologically deep tree's scan time
  bounded, not just its own recursion depth.
