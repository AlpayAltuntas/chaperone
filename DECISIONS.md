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
