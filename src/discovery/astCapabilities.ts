import ts from 'typescript';
import { splitWordSegments } from './wordSegments.js';

// AST-based capability detection (improvement_plan.md 1.1), replacing
// the original regex-over-raw-text approach. Tracks real import/require
// bindings and matches call expressions against them instead of matching
// text patterns — fixes the two failure classes the regex approach had:
//
// - False positives: a pattern appearing in a comment or string literal
//   (e.g. `// this skill can delete files`) used to trip the check even
//   though no such code exists. Comments and string contents are never
//   visited here — the AST simply doesn't represent them as executable
//   nodes.
// - False negatives: dynamic property access (`child_process['exec']`,
//   handled below via string-literal element access), aliased imports
//   (`import { exec as run }`, resolved back to the original exported
//   name), and the word-boundary bug (`\bdelete\b` never matched
//   `deleteFile` — a real standalone-word split via splitWordSegments
//   fixes this for identifier names, the same fix configParser.ts
//   already applies to config keys).
//
// Known remaining gaps (documented, not solved — see DECISIONS.md):
// arbitrary indirection (`const run = exec; run(cmd)`), a function
// reference passed across files/modules, fully dynamic requires
// (`require(moduleNameVariable)`), and a local declaration shadowing a
// bare-global name (`fetch`/`eval`/`Function`) are still invisible —
// this is static, single-file analysis, not real data-flow/points-to
// analysis or scope resolution.

export interface DetectedCapabilities {
  shellExec: boolean;
  fileSystemAccess: boolean;
  fileSystemScoped: boolean;
  networkAccess: boolean;
  destructiveKeywords: string[];
  dynamicEval: boolean;
  dataFlowToShellExec: boolean;
}

const EMPTY_CAPABILITIES: DetectedCapabilities = {
  shellExec: false,
  fileSystemAccess: false,
  fileSystemScoped: false,
  networkAccess: false,
  destructiveKeywords: [],
  dynamicEval: false,
  dataFlowToShellExec: false,
};

// eval()/Function() (bare or `new Function(...)`) — improvement_plan.md
// 2.6. Flagged unconditionally, regardless of what's passed to them: a
// decode-then-execute chain like `eval(atob(payload))` is just a call
// whose argument happens to itself be a call — already covered by
// flagging eval/Function at all, no separate atob-specific pattern
// needed.
const DYNAMIC_EVAL_GLOBAL_NAMES = new Set(['eval', 'Function']);

// Taint *sources* for the CHAP-INJ-002 data-flow improvement
// (improvement_plan.md 1.16) — read-oriented fs functions, distinct from
// FS_WRITE_FUNCTIONS above (a write result isn't attacker-controlled
// data flowing *in*).
const FS_READ_FUNCTIONS = new Set(['readFile', 'readFileSync', 'readdir', 'readdirSync']);

const SHELL_MODULES = new Set(['child_process', 'node:child_process']);
const SHELL_FUNCTIONS = new Set([
  'exec',
  'execSync',
  'spawn',
  'spawnSync',
  'execFile',
  'execFileSync',
]);

const FS_MODULES = new Set(['fs', 'node:fs', 'fs/promises', 'node:fs/promises']);
const FS_WRITE_FUNCTIONS = new Set([
  'writeFile',
  'writeFileSync',
  'unlink',
  'unlinkSync',
  'rm',
  'rmSync',
  'rmdir',
  'rmdirSync',
  'appendFile',
  'appendFileSync',
]);

const PATH_MODULES = new Set(['path', 'node:path']);
const PATH_SCOPING_FUNCTIONS = new Set(['join', 'resolve']);

const NETWORK_MODULES = new Set([
  'http',
  'https',
  'node:http',
  'node:https',
  'node-fetch',
  'axios',
]);

const WORKSPACE_NAME_SEGMENTS = new Set(['workspace', 'sandbox', 'scoped']);

const DESTRUCTIVE_KEYWORDS = new Set([
  'delete',
  'send',
  'transfer',
  'purchase',
  'deploy',
  'remove',
  'pay',
]);

type BindingKind = 'namespace' | 'named';

interface Binding {
  module: string;
  kind: BindingKind;
  // For 'named': the ORIGINAL exported name (not the local alias) — so
  // `import { exec as run } from 'child_process'` still resolves `run(x)`
  // back to child_process's `exec`. Unused ('') for 'namespace'.
  functionName: string;
}

interface CallTarget {
  module: string;
  functionName: string;
}

/**
 * Parses one skill source file and detects its capabilities. Never
 * throws — the TypeScript parser is resilient to malformed input (it
 * produces best-effort/partial nodes rather than throwing), so a
 * genuinely unparseable file just yields no detected capabilities rather
 * than failing the whole scan.
 */
export function detectCapabilities(filename: string, source: string): DetectedCapabilities {
  let sourceFile: ts.SourceFile;
  try {
    sourceFile = ts.createSourceFile(
      filename,
      source,
      ts.ScriptTarget.Latest,
      true,
      /^\.(ts|mts|cts)$/.test(getExtension(filename)) ? ts.ScriptKind.TS : ts.ScriptKind.JS,
    );
  } catch {
    return EMPTY_CAPABILITIES;
  }

  const bindings = new Map<string, Binding>();
  collectBindings(sourceFile, bindings);

  let shellExec = false;
  let fileSystemAccess = false;
  let fileSystemScoped = false;
  let networkAccess = false;
  let dynamicEval = false;
  const destructiveKeywords = new Set<string>();

  const recordDestructive = (name: string): void => {
    for (const segment of splitWordSegments(name)) {
      if (DESTRUCTIVE_KEYWORDS.has(segment)) {
        destructiveKeywords.add(segment);
      }
    }
  };

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;

      // fetch(...) is a global in modern Node — no import required —
      // unless the file itself has shadowed/rebound the name.
      if (ts.isIdentifier(callee) && callee.text === 'fetch' && !bindings.has('fetch')) {
        networkAccess = true;
      }

      if (
        ts.isIdentifier(callee) &&
        DYNAMIC_EVAL_GLOBAL_NAMES.has(callee.text) &&
        !bindings.has(callee.text)
      ) {
        dynamicEval = true;
      }

      const target = resolveCallTarget(callee, bindings);
      if (target !== null) {
        if (SHELL_MODULES.has(target.module) && SHELL_FUNCTIONS.has(target.functionName)) {
          shellExec = true;
        }
        if (FS_MODULES.has(target.module) && FS_WRITE_FUNCTIONS.has(target.functionName)) {
          fileSystemAccess = true;
        }
        if (
          PATH_MODULES.has(target.module) &&
          PATH_SCOPING_FUNCTIONS.has(target.functionName) &&
          isDirnameArgument(node.arguments[0])
        ) {
          fileSystemScoped = true;
        }
        if (NETWORK_MODULES.has(target.module)) {
          networkAccess = true;
        }
      }

      const calleeName = getCalleeSimpleName(callee);
      if (calleeName !== null) {
        recordDestructive(calleeName);
      }
    }

    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'Function' &&
      !bindings.has('Function')
    ) {
      dynamicEval = true;
    }

    if (isNamedFunctionLike(node)) {
      const name = getFunctionLikeDeclaredName(node);
      if (name !== null) {
        recordDestructive(name);
      }
    }

    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      const segments = splitWordSegments(node.name.text);
      if (segments.some((segment) => WORKSPACE_NAME_SEGMENTS.has(segment))) {
        fileSystemScoped = true;
      }
    }

    ts.forEachChild(node, visit);
  };
  visit(sourceFile);

  return {
    shellExec,
    fileSystemAccess,
    fileSystemScoped,
    networkAccess,
    destructiveKeywords: [...destructiveKeywords].sort(),
    dynamicEval,
    dataFlowToShellExec: detectDataFlowToShellExec(sourceFile, bindings),
  };
}

/** Merges per-file results the way discovery aggregates a whole skill: any file exercising a capability is enough, keyword findings union across files. */
export function mergeCapabilities(results: readonly DetectedCapabilities[]): DetectedCapabilities {
  const merged = { ...EMPTY_CAPABILITIES, destructiveKeywords: new Set<string>() };
  for (const result of results) {
    merged.shellExec ||= result.shellExec;
    merged.fileSystemAccess ||= result.fileSystemAccess;
    merged.fileSystemScoped ||= result.fileSystemScoped;
    merged.networkAccess ||= result.networkAccess;
    merged.dynamicEval ||= result.dynamicEval;
    merged.dataFlowToShellExec ||= result.dataFlowToShellExec;
    for (const keyword of result.destructiveKeywords) {
      merged.destructiveKeywords.add(keyword);
    }
  }
  return { ...merged, destructiveKeywords: [...merged.destructiveKeywords].sort() };
}

/**
 * A bounded, intra-file taint analysis for the CHAP-INJ-002 data-flow
 * improvement (improvement_plan.md 1.16): does a network/fs-read
 * result actually reach a shell-exec call's argument, rather than just
 * "both capabilities present somewhere in the file"? Tracks taint
 * through simple variable assignment and one level of method-call
 * chaining (`const res = await fetch(x); const body = await res.text();
 * exec(body)` — the exact shape the command-relay fixture demonstrates),
 * via fixed-point propagation over the file's variable declarations, not
 * scope-aware (the whole file is treated as one flat scope, same
 * simplification the rest of this module already makes for bindings).
 * Known gap, not solved: reassignment, destructuring, and control flow
 * (a branch that never actually executes) aren't modeled — this raises
 * confidence over a pure shape-match, it doesn't prove exploitability.
 */
function detectDataFlowToShellExec(
  sourceFile: ts.SourceFile,
  bindings: Map<string, Binding>,
): boolean {
  const declarations: Array<{ name: string; initializer: ts.Expression }> = [];
  const shellExecCalls: ts.CallExpression[] = [];

  const collect = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      declarations.push({ name: node.name.text, initializer: unwrapAwait(node.initializer) });
    }
    if (ts.isCallExpression(node)) {
      const target = resolveCallTarget(node.expression, bindings);
      if (
        target !== null &&
        SHELL_MODULES.has(target.module) &&
        SHELL_FUNCTIONS.has(target.functionName)
      ) {
        shellExecCalls.push(node);
      }
    }
    ts.forEachChild(node, collect);
  };
  collect(sourceFile);

  const isTaintSourceCall = (expr: ts.Expression): boolean => {
    if (!ts.isCallExpression(expr)) {
      return false;
    }
    if (
      ts.isIdentifier(expr.expression) &&
      expr.expression.text === 'fetch' &&
      !bindings.has('fetch')
    ) {
      return true;
    }
    const target = resolveCallTarget(expr.expression, bindings);
    if (target === null) {
      return false;
    }
    return (
      NETWORK_MODULES.has(target.module) ||
      (FS_MODULES.has(target.module) && FS_READ_FUNCTIONS.has(target.functionName))
    );
  };

  const tainted = new Set<string>();
  for (const decl of declarations) {
    if (isTaintSourceCall(decl.initializer)) {
      tainted.add(decl.name);
    }
  }

  let changed = true;
  for (let iteration = 0; changed && iteration < 5; iteration++) {
    changed = false;
    for (const decl of declarations) {
      if (!tainted.has(decl.name) && expressionReferencesTainted(decl.initializer, tainted)) {
        tainted.add(decl.name);
        changed = true;
      }
    }
  }

  return shellExecCalls.some((call) =>
    call.arguments.some((arg) => expressionReferencesTainted(arg, tainted)),
  );
}

function expressionReferencesTainted(expr: ts.Expression, tainted: Set<string>): boolean {
  if (ts.isIdentifier(expr)) {
    return tainted.has(expr.text);
  }
  if (ts.isCallExpression(expr)) {
    if (expressionReferencesTainted(expr.expression, tainted)) {
      return true;
    }
    return expr.arguments.some((arg) => expressionReferencesTainted(arg, tainted));
  }
  if (ts.isPropertyAccessExpression(expr)) {
    return expressionReferencesTainted(expr.expression, tainted);
  }
  if (ts.isTemplateExpression(expr)) {
    return expr.templateSpans.some((span) => expressionReferencesTainted(span.expression, tainted));
  }
  if (ts.isBinaryExpression(expr)) {
    return (
      expressionReferencesTainted(expr.left, tainted) ||
      expressionReferencesTainted(expr.right, tainted)
    );
  }
  if (ts.isParenthesizedExpression(expr) || ts.isAwaitExpression(expr)) {
    return expressionReferencesTainted(expr.expression, tainted);
  }
  return false;
}

function unwrapAwait(expr: ts.Expression): ts.Expression {
  return ts.isAwaitExpression(expr) ? expr.expression : expr;
}

function getExtension(filename: string): string {
  const dot = filename.lastIndexOf('.');
  return dot === -1 ? '' : filename.slice(dot).toLowerCase();
}

function isDirnameArgument(arg: ts.Expression | undefined): boolean {
  return arg !== undefined && ts.isIdentifier(arg) && arg.text === '__dirname';
}

function collectBindings(root: ts.Node, bindings: Map<string, Binding>): void {
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      collectImportBindings(node, node.moduleSpecifier.text, bindings);
    }

    if (ts.isVariableDeclaration(node) && node.initializer) {
      const requiredModule = unwrapRequireCall(node.initializer);
      if (requiredModule !== null) {
        collectRequireBindings(node.name, requiredModule, bindings);
      }
    }

    ts.forEachChild(node, visit);
  };
  visit(root);
}

function collectImportBindings(
  node: ts.ImportDeclaration,
  moduleSpecifier: string,
  bindings: Map<string, Binding>,
): void {
  const clause = node.importClause;
  if (!clause) {
    return;
  }
  if (clause.name) {
    // Default import — treated like a namespace binding (`import axios
    // from 'axios'; axios(url)` is a real, common pattern).
    bindings.set(clause.name.text, {
      module: moduleSpecifier,
      kind: 'namespace',
      functionName: '',
    });
  }
  const namedBindings = clause.namedBindings;
  if (namedBindings && ts.isNamespaceImport(namedBindings)) {
    bindings.set(namedBindings.name.text, {
      module: moduleSpecifier,
      kind: 'namespace',
      functionName: '',
    });
  } else if (namedBindings && ts.isNamedImports(namedBindings)) {
    for (const specifier of namedBindings.elements) {
      const original = (specifier.propertyName ?? specifier.name).text;
      bindings.set(specifier.name.text, {
        module: moduleSpecifier,
        kind: 'named',
        functionName: original,
      });
    }
  }
}

function collectRequireBindings(
  name: ts.BindingName,
  moduleSpecifier: string,
  bindings: Map<string, Binding>,
): void {
  if (ts.isIdentifier(name)) {
    bindings.set(name.text, { module: moduleSpecifier, kind: 'namespace', functionName: '' });
    return;
  }
  if (ts.isObjectBindingPattern(name)) {
    for (const element of name.elements) {
      if (!ts.isIdentifier(element.name)) {
        continue;
      }
      const original =
        element.propertyName && ts.isIdentifier(element.propertyName)
          ? element.propertyName.text
          : element.name.text;
      bindings.set(element.name.text, {
        module: moduleSpecifier,
        kind: 'named',
        functionName: original,
      });
    }
  }
}

function unwrapRequireCall(expr: ts.Expression): string | null {
  if (
    !ts.isCallExpression(expr) ||
    !ts.isIdentifier(expr.expression) ||
    expr.expression.text !== 'require'
  ) {
    return null;
  }
  const arg = expr.arguments[0];
  return arg !== undefined && ts.isStringLiteral(arg) ? arg.text : null;
}

function resolveCallTarget(
  callee: ts.Expression,
  bindings: Map<string, Binding>,
): CallTarget | null {
  if (ts.isIdentifier(callee)) {
    const binding = bindings.get(callee.text);
    if (!binding) {
      return null;
    }
    // A named binding IS the function itself (`exec(...)`); a
    // namespace/default binding called bare means the module's own
    // export was invoked directly (`axios(url)`).
    return {
      module: binding.module,
      functionName: binding.kind === 'named' ? binding.functionName : '',
    };
  }

  if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
    const binding = bindings.get(callee.expression.text);
    if (!binding || binding.kind !== 'namespace') {
      return null;
    }
    return { module: binding.module, functionName: callee.name.text };
  }

  if (
    ts.isElementAccessExpression(callee) &&
    ts.isIdentifier(callee.expression) &&
    ts.isStringLiteralLike(callee.argumentExpression)
  ) {
    const binding = bindings.get(callee.expression.text);
    if (!binding || binding.kind !== 'namespace') {
      return null;
    }
    return { module: binding.module, functionName: callee.argumentExpression.text };
  }

  return null;
}

function getCalleeSimpleName(callee: ts.Expression): string | null {
  if (ts.isIdentifier(callee)) {
    return callee.text;
  }
  if (ts.isPropertyAccessExpression(callee)) {
    return callee.name.text;
  }
  if (ts.isElementAccessExpression(callee) && ts.isStringLiteralLike(callee.argumentExpression)) {
    return callee.argumentExpression.text;
  }
  return null;
}

function isNamedFunctionLike(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node)
  );
}

function getFunctionLikeDeclaredName(node: ts.Node): string | null {
  if (ts.isFunctionDeclaration(node) && node.name) {
    return node.name.text;
  }
  if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) {
    return node.name.text;
  }
  if (ts.isFunctionExpression(node) && node.name) {
    return node.name.text;
  }
  if (ts.isFunctionExpression(node) || ts.isArrowFunction(node)) {
    const parent = node.parent as ts.Node | undefined;
    if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }
    if (parent && ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }
  }
  return null;
}
