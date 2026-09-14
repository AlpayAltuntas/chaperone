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
