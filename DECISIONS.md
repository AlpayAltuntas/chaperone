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
