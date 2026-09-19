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
