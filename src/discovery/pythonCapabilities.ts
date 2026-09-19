import type { DetectedCapabilities } from './astCapabilities.js';

// Python capability detection (improvement_plan.md 1.9/Phase 16) — a
// regex-over-raw-text first cut, explicitly NOT held to the AST-based
// bar Phase 10 set for JS/TS. This is a deliberate, documented v1
// limitation for Python (no `python` AST/tokenizer dependency exists in
// this project, and adding one is a bigger bet than a "first cut"
// warrants) — same fragility class as the pre-Phase-10 JS approach: a
// pattern inside a comment or string literal can false-positive, and an
// unconventional spelling (e.g. a wrapped/aliased call) can false-negative.
// See DECISIONS.md, Phase 16.

const SHELL_EXEC_PATTERNS = [
  /\bsubprocess\.(?:run|call|check_call|check_output|Popen)\(/,
  /\bos\.system\(/,
  /\bos\.popen\(/,
];

const FS_WRITE_PATTERNS = [
  /\bos\.(?:remove|unlink|rmdir|removedirs)\(/,
  /\bshutil\.(?:rmtree|move)\(/,
  // Bounded to one line (not `[^)]*`, which a nested call in the path
  // argument — e.g. `open(os.path.join(...), "w")` — would defeat by
  // hitting that inner call's closing paren first).
  /\bopen\([^\n]*,\s*['"]a?[wx]b?['"]/,
];

// Evidence that file access is scoped to a fixed base directory rather
// than an arbitrary caller-supplied path — the same proxy signal
// astCapabilities.ts uses for JS/TS (CHAP-AGY-002).
const FS_SCOPING_PATTERNS = [
  /os\.path\.(?:join|abspath)\(\s*os\.path\.dirname\(__file__\)/,
  /\b\w*(?:WORKSPACE|SANDBOX|SCOPED)\w*\s*=/i,
];

const NETWORK_PATTERNS = [
  /\brequests\.(?:get|post|put|delete|patch|head|request)\(/,
  /\burllib\.request\b/,
  /\bhttp\.client\b/,
  /\bsocket\.socket\(/,
];

// Python's eval() and exec() are its dynamic-code-execution primitives —
// the same semantic category astCapabilities.ts flags as `dynamicEval`
// for JS's eval()/Function(). __import__() is included as the dynamic
// equivalent of a computed `import`.
const DYNAMIC_EVAL_PATTERNS = [/\beval\(/, /\bexec\(/, /\b__import__\(/];

const DESTRUCTIVE_KEYWORDS = ['delete', 'send', 'transfer', 'purchase', 'deploy', 'remove', 'pay'];

/**
 * Regex-based Python capability detection — deliberately simpler than
 * `detectCapabilities` (astCapabilities.ts): no import/binding
 * resolution, no data-flow tracking. `dataFlowToShellExec` is always
 * `false` here; Phase 16's scope is capability *detection*, not porting
 * CHAP-INJ-002's taint analysis to a second language.
 */
export function detectPythonCapabilities(source: string): DetectedCapabilities {
  return {
    shellExec: SHELL_EXEC_PATTERNS.some((re) => re.test(source)),
    fileSystemAccess: FS_WRITE_PATTERNS.some((re) => re.test(source)),
    fileSystemScoped: FS_SCOPING_PATTERNS.some((re) => re.test(source)),
    networkAccess: NETWORK_PATTERNS.some((re) => re.test(source)),
    dynamicEval: DYNAMIC_EVAL_PATTERNS.some((re) => re.test(source)),
    destructiveKeywords: DESTRUCTIVE_KEYWORDS.filter((kw) =>
      new RegExp(`\\b${kw}\\b`, 'i').test(source),
    ).sort(),
    dataFlowToShellExec: false,
  };
}
