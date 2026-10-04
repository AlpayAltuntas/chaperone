import type { CapabilityEvidence } from '../model/types.js';
import type { DetectedCapabilities } from './astCapabilities.js';
import { splitWordSegments } from './wordSegments.js';

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

const DESTRUCTIVE_KEYWORDS = new Set([
  'delete',
  'send',
  'transfer',
  'purchase',
  'deploy',
  'remove',
  'pay',
]);

// A module-level function definition: the skill's public surface. Only
// these names count toward destructive keywords, so a keyword in a
// comment, a string, or a local helper doesn't (PROPOSED_FIXES.md 2.4).
const MODULE_LEVEL_DEF = /^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm;

/**
 * Regex-based Python capability detection — deliberately simpler than
 * `detectCapabilities` (astCapabilities.ts): no import/binding
 * resolution, no data-flow tracking. `dataFlowToShellExec` is always
 * `false` here; Phase 16's scope is capability *detection*, not porting
 * CHAP-INJ-002's taint analysis to a second language.
 */
export function detectPythonCapabilities(source: string, file = '<python>'): DetectedCapabilities {
  const evidence: CapabilityEvidence[] = [
    ...findEvidence(source, file, 'shellExec', SHELL_EXEC_PATTERNS),
    ...findEvidence(source, file, 'networkAccess', NETWORK_PATTERNS),
    ...findEvidence(source, file, 'dynamicEval', DYNAMIC_EVAL_PATTERNS),
  ];
  const scoped = FS_SCOPING_PATTERNS.some((re) => re.test(source));
  evidence.push(
    ...findEvidence(source, file, 'fileSystemAccess', FS_WRITE_PATTERNS).map((item) => ({
      ...item,
      scoped,
    })),
  );

  const destructiveKeywords = new Set<string>();
  for (const match of source.matchAll(MODULE_LEVEL_DEF)) {
    const name = match[1] ?? '';
    const keywords = splitWordSegments(name).filter((segment) => DESTRUCTIVE_KEYWORDS.has(segment));
    if (keywords.length > 0) {
      keywords.forEach((keyword) => destructiveKeywords.add(keyword));
      evidence.push({
        capability: 'destructive',
        file,
        line: lineOf(source, match.index),
        api: name,
      });
    }
  }

  const has = (capability: CapabilityEvidence['capability']): boolean =>
    evidence.some((e) => e.capability === capability);
  return {
    shellExec: has('shellExec'),
    fileSystemAccess: has('fileSystemAccess'),
    fileSystemScoped: scoped,
    networkAccess: has('networkAccess'),
    dynamicEval: has('dynamicEval'),
    destructiveKeywords: [...destructiveKeywords].sort(),
    dataFlowToShellExec: false,
    evidence,
  };
}

function findEvidence(
  source: string,
  file: string,
  capability: CapabilityEvidence['capability'],
  patterns: readonly RegExp[],
): CapabilityEvidence[] {
  const found: CapabilityEvidence[] = [];
  for (const pattern of patterns) {
    const global = new RegExp(
      pattern.source,
      pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`,
    );
    for (const match of source.matchAll(global)) {
      found.push({
        capability,
        file,
        line: lineOf(source, match.index),
        api: match[0].replace(/\($/, '').trim(),
      });
    }
  }
  return found.sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
}

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (source.charCodeAt(i) === 10) {
      line++;
    }
  }
  return line;
}
