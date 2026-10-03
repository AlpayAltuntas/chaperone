import ts from 'typescript';
import type { CapabilityEvidence } from '../model/types.js';
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
// Also resolved (PROPOSED_FIXES.md 3.2): one level of aliasing
// (`const run = cp['exec']; run(c)`), nested namespaces
// (`fs.promises.writeFile`, `require('fs').promises.x`), template-literal
// keys (``cp[`exec`]``), and indirect eval (`(0, eval)(c)`,
// `globalThis.eval(c)`).
//
// Known remaining gaps (documented, not solved — see DECISIONS.md):
// aliasing more than a few levels deep, a function reference passed
// across files/modules, and a *parameter* shadowing a bare-global name
// (`fetch`/`eval`) are still invisible. Locally declared names do shadow
// globals, but scope is flat: this is static, single-file analysis, not
// real data-flow/points-to analysis or scope resolution.

export interface DetectedCapabilities {
  shellExec: boolean;
  fileSystemAccess: boolean;
  fileSystemScoped: boolean;
  networkAccess: boolean;
  destructiveKeywords: string[];
  dynamicEval: boolean;
  dataFlowToShellExec: boolean;
  evidence: CapabilityEvidence[];
}

// Per capability, per skill. Enough to point at the first few call sites
// without one generated file flooding the model.
const MAX_EVIDENCE_PER_CAPABILITY = 10;

const EMPTY_CAPABILITIES: DetectedCapabilities = {
  shellExec: false,
  fileSystemAccess: false,
  fileSystemScoped: false,
  networkAccess: false,
  destructiveKeywords: [],
  dynamicEval: false,
  dataFlowToShellExec: false,
  evidence: [],
};

// eval()/Function() (bare or `new Function(...)`) — improvement_plan.md
// 2.6. Flagged unconditionally, regardless of what's passed to them: a
// decode-then-execute chain like `eval(atob(payload))` is just a call
// whose argument happens to itself be a call — already covered by
// flagging eval/Function at all, no separate atob-specific pattern
// needed.
const DYNAMIC_EVAL_GLOBAL_NAMES = new Set(['eval', 'Function']);

// Global objects `eval`/`Function` can be reached through
// (`globalThis.eval(c)`, `self['eval'](c)`).
const GLOBAL_OBJECT_NAMES = new Set(['globalThis', 'global', 'window', 'self']);

// Taint *sources* for the CHAP-INJ-002 data-flow improvement
// (improvement_plan.md 1.16) — read-oriented fs functions, distinct from
// FS_WRITE_FUNCTIONS below (a write result isn't attacker-controlled
// data flowing *in*).
const FS_READ_FUNCTIONS = new Set(['readFile', 'readFileSync', 'readdir', 'readdirSync']);

// Module names are compared without a `node:` prefix (see normalizeModule).
// `''` as a function name means the module's default export was called
// directly (`execa(cmd)`, `crossSpawn(cmd)`).
const SHELL_FUNCTIONS_BY_MODULE: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  [
    'child_process',
    new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']),
  ],
  [
    'execa',
    new Set(['', 'execa', 'execaSync', 'execaCommand', 'execaCommandSync', 'execaNode', '$']),
  ],
  ['shelljs', new Set(['exec'])],
  ['zx', new Set(['$'])],
  ['cross-spawn', new Set(['', 'spawn', 'sync'])],
  ['node-pty', new Set(['spawn'])],
]);

const FS_MODULES = new Set(['fs', 'fs/promises', 'fs-extra', 'graceful-fs']);
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
  'rename',
  'renameSync',
  'copyFile',
  'copyFileSync',
  'cp',
  'cpSync',
  'mkdir',
  'mkdirSync',
  'truncate',
  'truncateSync',
  'chmod',
  'chmodSync',
  'chown',
  'chownSync',
  'symlink',
  'symlinkSync',
  'link',
  'linkSync',
  'createWriteStream',
  // fs-extra
  'outputFile',
  'outputFileSync',
  'outputJson',
  'outputJsonSync',
  'writeJson',
  'writeJsonSync',
  'remove',
  'removeSync',
  'emptyDir',
  'emptyDirSync',
  'move',
  'moveSync',
  'copy',
  'copySync',
]);
// Writes whose second argument is also a destination path.
const TWO_PATH_FS_FUNCTIONS = new Set([
  'rename',
  'renameSync',
  'copyFile',
  'copyFileSync',
  'cp',
  'cpSync',
  'symlink',
  'symlinkSync',
  'link',
  'linkSync',
  'move',
  'moveSync',
  'copy',
  'copySync',
]);
// Modules whose every call is a filesystem write/delete.
const FS_WRITE_MODULES = new Set(['rimraf', 'del']);

const PATH_MODULES = new Set(['path']);
const PATH_SCOPING_FUNCTIONS = new Set(['join', 'resolve']);

// Any call into (or `new` of) one of these is network access.
const NETWORK_MODULES = new Set([
  'http',
  'https',
  'http2',
  'net',
  'tls',
  'dgram',
  'node-fetch',
  'cross-fetch',
  'axios',
  'undici',
  'got',
  'ky',
  'superagent',
  'request',
  'ws',
]);
// Global network constructors/functions, when not shadowed by a binding.
const NETWORK_GLOBAL_CALLS = new Set(['fetch']);
const NETWORK_GLOBAL_CONSTRUCTORS = new Set(['WebSocket', 'XMLHttpRequest', 'EventSource']);

// `vm` executes arbitrary code strings, the same capability as eval.
const VM_EVAL_FUNCTIONS = new Set([
  'runInNewContext',
  'runInThisContext',
  'runInContext',
  'compileFunction',
  'Script',
  'SourceTextModule',
]);
// `setTimeout('code', ms)` evaluates a string argument like eval.
const STRING_EVAL_TIMERS = new Set(['setTimeout', 'setInterval']);

const DESTRUCTIVE_KEYWORDS = new Set([
  'delete',
  'send',
  'transfer',
  'purchase',
  'deploy',
  'remove',
  'pay',
]);

// A *member* call whose whole name is one of these bare verbs (`res.send`,
// `cache.delete`, `classList.remove`) is almost always a container,
// response, socket, or DOM method rather than the skill's own irreversible
// action, so it doesn't count toward destructiveKeywords. A more specific
// member name (`client.sendEmail`), a bare call (`send(x)`), or a declared
// function name (`function deleteFile`) still does — PROPOSED_FIXES.md 2.4.
const GENERIC_MEMBER_VERBS = new Set(['delete', 'remove', 'send']);

/**
 * What a local name refers to: a module plus the member path inside it.
 * `const cp = require('child_process')` is `{child_process, []}`;
 * `import { exec as run } from 'child_process'` is `{child_process,
 * ['exec']}` (the ORIGINAL exported name, so the alias still resolves);
 * `const { promises } = require('fs')` is `{fs, ['promises']}`.
 */
interface Binding {
  module: string;
  path: readonly string[];
}

interface CallTarget {
  module: string;
  /** The last member name, or '' when the module itself was called (`axios(url)`). */
  functionName: string;
  /** The full member path inside the module (`['promises', 'writeFile']`). */
  path: readonly string[];
}

/**
 * Parses one skill source file and detects its capabilities. Never
 * throws — the TypeScript parser is resilient to malformed input (it
 * produces best-effort/partial nodes rather than throwing), so a
 * genuinely unparseable file just yields no detected capabilities rather
 * than failing the whole scan.
 */
export function detectCapabilities(
  filename: string,
  source: string,
  /** The path recorded in evidence, when `filename` is only a parser hint (an extensionless script parsed as `.js`). */
  evidenceFile: string = filename,
): DetectedCapabilities {
  let sourceFile: ts.SourceFile;
  try {
    sourceFile = ts.createSourceFile(
      filename,
      source,
      ts.ScriptTarget.Latest,
      true,
      scriptKindFor(getExtension(filename)),
    );
  } catch {
    return EMPTY_CAPABILITIES;
  }

  const declared = collectDeclaredNames(sourceFile);
  const bindings = new Map<string, Binding>();
  const evalAliases = new Set<string>();
  collectBindings(sourceFile, bindings, declared, evalAliases);
  const scopedPaths = new ScopedPathResolver(
    sourceFile,
    bindings,
    collectModuleDirAliases(sourceFile),
  );

  const evidence: CapabilityEvidence[] = [];
  const destructiveKeywords = new Set<string>();

  const record = (
    capability: CapabilityEvidence['capability'],
    node: ts.Node,
    api: string,
    scoped?: boolean,
  ): void => {
    const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
    evidence.push({
      capability,
      file: evidenceFile,
      line,
      api,
      ...(scoped === undefined ? {} : { scoped }),
    });
  };

  const recordDestructive = (node: ts.Node, name: string): void => {
    let matched = false;
    for (const segment of splitWordSegments(name)) {
      if (DESTRUCTIVE_KEYWORDS.has(segment)) {
        destructiveKeywords.add(segment);
        matched = true;
      }
    }
    if (matched) {
      record('destructive', node, name);
    }
  };

  const recordTarget = (
    node: ts.Node,
    target: CallTarget | null,
    args: readonly ts.Expression[],
  ): void => {
    if (target === null) {
      return;
    }
    const api = describeTarget(target);
    if (isShellTarget(target)) {
      record('shellExec', node, api);
    }
    if (isFsWriteTarget(target)) {
      const pathArgs = TWO_PATH_FS_FUNCTIONS.has(target.functionName)
        ? args.slice(0, 2)
        : args.slice(0, 1);
      const scoped = pathArgs.length > 0 && pathArgs.every((arg) => scopedPaths.isScoped(arg));
      record('fileSystemAccess', node, api, scoped);
    }
    if (NETWORK_MODULES.has(target.module)) {
      record('networkAccess', node, api);
    }
    if (target.module === 'vm' && VM_EVAL_FUNCTIONS.has(target.functionName)) {
      record('dynamicEval', node, api);
    }
  };

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;

      if (
        ts.isIdentifier(callee) &&
        NETWORK_GLOBAL_CALLS.has(callee.text) &&
        !declared.has(callee.text)
      ) {
        record('networkAccess', node, callee.text);
      }

      // globalThis.fetch(url)
      const globalMember = getMemberAccess(callee);
      if (
        globalMember !== null &&
        ts.isIdentifier(globalMember.object) &&
        GLOBAL_OBJECT_NAMES.has(globalMember.object.text) &&
        !declared.has(globalMember.object.text) &&
        NETWORK_GLOBAL_CALLS.has(globalMember.name)
      ) {
        record('networkAccess', node, `${globalMember.object.text}.${globalMember.name}`);
      }

      if (isEvalReference(callee, declared, evalAliases)) {
        record('dynamicEval', node, describeExpression(callee));
      }

      // require(<non-literal>) / import(<non-literal>): the module that
      // runs can't be known statically, which is how loaders hide payloads.
      if (isDynamicModuleLoad(node, declared)) {
        record(
          'dynamicEval',
          node,
          callee.kind === ts.SyntaxKind.ImportKeyword ? 'import(<dynamic>)' : 'require(<dynamic>)',
        );
      }

      // setTimeout('code', ms) / setInterval(`code`, ms).
      if (
        ts.isIdentifier(callee) &&
        STRING_EVAL_TIMERS.has(callee.text) &&
        !declared.has(callee.text) &&
        node.arguments[0] !== undefined &&
        isStringExpression(node.arguments[0])
      ) {
        record('dynamicEval', node, `${callee.text}(<string>)`);
      }

      // module._compile(source, filename)
      if (
        ts.isPropertyAccessExpression(callee) &&
        callee.name.text === '_compile' &&
        ts.isIdentifier(callee.expression) &&
        callee.expression.text === 'module' &&
        !declared.has('module')
      ) {
        record('dynamicEval', node, 'module._compile');
      }

      // Bun.spawn / Bun.spawnSync (Bun runtime global).
      if (isRuntimeGlobalMember(callee, 'Bun', ['spawn', 'spawnSync', '$'], declared)) {
        record('shellExec', node, describeExpression(callee));
      }

      recordTarget(node, resolveCallTarget(callee, bindings), node.arguments);

      const calleeName = getCalleeSimpleName(callee);
      if (calleeName !== null && !isGenericMemberVerbCall(callee, calleeName)) {
        recordDestructive(node, calleeName);
      }
    }

    // zx/execa tagged templates: $`rm -rf ${dir}`.
    if (ts.isTaggedTemplateExpression(node)) {
      recordTarget(node, resolveCallTarget(node.tag, bindings), []);
    }

    if (ts.isNewExpression(node)) {
      const ctor = node.expression;
      if (isEvalReference(ctor, declared, evalAliases)) {
        record('dynamicEval', node, `new ${describeExpression(ctor)}`);
      }
      if (
        ts.isIdentifier(ctor) &&
        NETWORK_GLOBAL_CONSTRUCTORS.has(ctor.text) &&
        !declared.has(ctor.text)
      ) {
        record('networkAccess', node, `new ${ctor.text}`);
      }
      // new Deno.Command('sh', ...) (Deno runtime global).
      if (isRuntimeGlobalMember(ctor, 'Deno', ['Command'], declared)) {
        record('shellExec', node, 'new Deno.Command');
      }
      recordTarget(node, resolveCallTarget(ctor, bindings), node.arguments ?? []);
    }

    if (isNamedFunctionLike(node)) {
      const name = getFunctionLikeDeclaredName(node);
      if (name !== null) {
        recordDestructive(node, name);
      }
    }

    ts.forEachChild(node, visit);
  };
  visit(sourceFile);

  const has = (capability: CapabilityEvidence['capability']): boolean =>
    evidence.some((e) => e.capability === capability);
  const writes = evidence.filter((e) => e.capability === 'fileSystemAccess');

  return {
    shellExec: has('shellExec'),
    fileSystemAccess: writes.length > 0,
    // Scoping is decided per write call: a file is scoped only when every
    // write in it is (PROPOSED_FIXES.md 2.6).
    fileSystemScoped: writes.length > 0 && writes.every((e) => e.scoped === true),
    networkAccess: has('networkAccess'),
    destructiveKeywords: [...destructiveKeywords].sort(),
    dynamicEval: has('dynamicEval'),
    dataFlowToShellExec: detectDataFlowToShellExec(sourceFile, bindings),
    evidence,
  };
}

/** Merges per-file results the way discovery aggregates a whole skill. */
export function mergeCapabilities(results: readonly DetectedCapabilities[]): DetectedCapabilities {
  const merged = { ...EMPTY_CAPABILITIES, destructiveKeywords: new Set<string>() };
  const evidence: CapabilityEvidence[] = [];
  const evidenceCounts = new Map<CapabilityEvidence['capability'], number>();
  const filesWithWrites = results.filter((result) => result.fileSystemAccess);
  for (const result of results) {
    merged.shellExec ||= result.shellExec;
    merged.fileSystemAccess ||= result.fileSystemAccess;
    merged.networkAccess ||= result.networkAccess;
    merged.dynamicEval ||= result.dynamicEval;
    merged.dataFlowToShellExec ||= result.dataFlowToShellExec;
    for (const keyword of result.destructiveKeywords) {
      merged.destructiveKeywords.add(keyword);
    }
    for (const item of result.evidence) {
      const count = evidenceCounts.get(item.capability) ?? 0;
      if (count < MAX_EVIDENCE_PER_CAPABILITY) {
        evidence.push(item);
        evidenceCounts.set(item.capability, count + 1);
      }
    }
  }
  return {
    ...merged,
    // A skill is scoped only when every file that writes is: one scoped
    // file no longer clears unscoped writes in another (PROPOSED_FIXES.md 2.6).
    fileSystemScoped:
      filesWithWrites.length > 0 && filesWithWrites.every((result) => result.fileSystemScoped),
    destructiveKeywords: [...merged.destructiveKeywords].sort(),
    evidence,
  };
}

/**
 * Decides whether a path expression is confined to a fixed place
 * (PROPOSED_FIXES.md 2.6): the module's own directory (`__dirname`,
 * `import.meta.dirname`/`url` and variables derived from them), a fixed
 * string path other than a filesystem root, a variable initialized from
 * either, or `path.join`/`path.resolve` whose first argument is one of
 * those. Anything else, such as a caller-supplied parameter, is unscoped.
 * Traversal through a joined segment (`../`) isn't modeled.
 */
class ScopedPathResolver {
  private readonly scopedVariables = new Set<string>();

  constructor(
    root: ts.SourceFile,
    private readonly bindings: ReadonlyMap<string, Binding>,
    private readonly moduleDirAliases: ReadonlySet<string>,
  ) {
    const declarations: Array<{ name: string; initializer: ts.Expression }> = [];
    const visit = (node: ts.Node): void => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        declarations.push({ name: node.name.text, initializer: node.initializer });
      }
      ts.forEachChild(node, visit);
    };
    visit(root);
    for (let pass = 0; pass < 5; pass++) {
      let changed = false;
      for (const { name, initializer } of declarations) {
        if (!this.scopedVariables.has(name) && this.isScoped(initializer)) {
          this.scopedVariables.add(name);
          changed = true;
        }
      }
      if (!changed) {
        break;
      }
    }
  }

  isScoped(expr: ts.Expression): boolean {
    const inner = unwrapParentheses(expr);
    if (ts.isAwaitExpression(inner)) {
      return this.isScoped(inner.expression);
    }
    if (ts.isIdentifier(inner)) {
      return (
        inner.text === '__dirname' ||
        this.moduleDirAliases.has(inner.text) ||
        this.scopedVariables.has(inner.text)
      );
    }
    if (ts.isStringLiteralLike(inner)) {
      return isFixedNonRootPath(inner.text);
    }
    if (ts.isArrayLiteralExpression(inner)) {
      return inner.elements.length > 0 && inner.elements.every((e) => this.isScoped(e));
    }
    if (ts.isTemplateExpression(inner)) {
      // `${__dirname}/out/${name}`: scoped when the leading part is.
      const first = inner.templateSpans[0];
      return inner.head.text === '' && first !== undefined && this.isScoped(first.expression);
    }
    if (ts.isBinaryExpression(inner) && inner.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return this.isScoped(inner.left);
    }
    if (ts.isCallExpression(inner)) {
      const target = resolveCallTarget(inner.expression, this.bindings);
      if (
        target !== null &&
        PATH_MODULES.has(target.module) &&
        PATH_SCOPING_FUNCTIONS.has(target.functionName)
      ) {
        const first = inner.arguments[0];
        return (
          first !== undefined &&
          (this.isScoped(first) || isModuleDirArgument(first, this.moduleDirAliases))
        );
      }
    }
    // new URL('./out', import.meta.url), path.dirname(fileURLToPath(import.meta.url)), ...
    return referencesImportMetaLocation(inner);
  }
}

/** A literal path that names a fixed location, not `/`, `~`, `.`, or a drive root. */
function isFixedNonRootPath(text: string): boolean {
  const trimmed = text.trim();
  return trimmed.length > 0 && !/^(?:[/\\]+|~[/\\]?|\.[/\\]?|[A-Za-z]:[/\\]?)$/.test(trimmed);
}

function describeTarget(target: CallTarget): string {
  return [target.module, ...target.path].join('.');
}

/** A short name for a callee (`globalThis.eval`, `(0, eval)`), never a source snippet. */
function describeExpression(expr: ts.Expression): string {
  const inner = unwrapParentheses(expr);
  if (ts.isIdentifier(inner)) {
    return inner.text;
  }
  if (ts.isBinaryExpression(inner) && inner.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    return `(0, ${describeExpression(inner.right)})`;
  }
  const member = getMemberAccess(inner);
  if (member !== null) {
    return `${describeExpression(member.object)}.${member.name}`;
  }
  return '<expression>';
}

function isShellTarget(target: CallTarget): boolean {
  return SHELL_FUNCTIONS_BY_MODULE.get(target.module)?.has(target.functionName) ?? false;
}

function isFsWriteTarget(target: CallTarget): boolean {
  return (
    (FS_MODULES.has(target.module) && FS_WRITE_FUNCTIONS.has(target.functionName)) ||
    FS_WRITE_MODULES.has(target.module)
  );
}

/** `eval`/`Function` reached directly, through a global object, via `(0, eval)`, or through a local alias. */
function isEvalReference(
  expr: ts.Expression,
  declared: ReadonlySet<string>,
  evalAliases: ReadonlySet<string>,
): boolean {
  const inner = unwrapParentheses(expr);
  if (ts.isIdentifier(inner)) {
    return (
      (DYNAMIC_EVAL_GLOBAL_NAMES.has(inner.text) && !declared.has(inner.text)) ||
      evalAliases.has(inner.text)
    );
  }
  // (0, eval)(c): the comma operator yields eval without a direct-eval call.
  if (ts.isBinaryExpression(inner) && inner.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    return isEvalReference(inner.right, declared, evalAliases);
  }
  const member = getMemberAccess(inner);
  if (
    member !== null &&
    ts.isIdentifier(member.object) &&
    GLOBAL_OBJECT_NAMES.has(member.object.text) &&
    !declared.has(member.object.text)
  ) {
    return DYNAMIC_EVAL_GLOBAL_NAMES.has(member.name);
  }
  return false;
}

function isDynamicModuleLoad(call: ts.CallExpression, declared: ReadonlySet<string>): boolean {
  const arg = call.arguments[0];
  if (arg === undefined || ts.isStringLiteralLike(arg)) {
    return false;
  }
  if (call.expression.kind === ts.SyntaxKind.ImportKeyword) {
    return true;
  }
  return (
    ts.isIdentifier(call.expression) &&
    call.expression.text === 'require' &&
    !declared.has('require')
  );
}

function isStringExpression(expr: ts.Expression): boolean {
  return (
    ts.isStringLiteralLike(expr) ||
    ts.isTemplateExpression(expr) ||
    (ts.isBinaryExpression(expr) &&
      expr.operatorToken.kind === ts.SyntaxKind.PlusToken &&
      (isStringExpression(expr.left) || isStringExpression(expr.right)))
  );
}

function isRuntimeGlobalMember(
  expr: ts.Expression,
  globalName: string,
  members: readonly string[],
  declared: ReadonlySet<string>,
): boolean {
  const member = getMemberAccess(expr);
  return (
    member !== null &&
    ts.isIdentifier(member.object) &&
    member.object.text === globalName &&
    !declared.has(globalName) &&
    members.includes(member.name)
  );
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
  bindings: ReadonlyMap<string, Binding>,
): boolean {
  const declarations: Array<{ name: string; initializer: ts.Expression }> = [];
  const shellExecCalls: ts.CallExpression[] = [];

  const collect = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      declarations.push({ name: node.name.text, initializer: unwrapAwait(node.initializer) });
    }
    if (ts.isCallExpression(node)) {
      const target = resolveCallTarget(node.expression, bindings);
      if (target !== null && isShellTarget(target)) {
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
      NETWORK_GLOBAL_CALLS.has(expr.expression.text) &&
      !bindings.has(expr.expression.text)
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

function scriptKindFor(extension: string): ts.ScriptKind {
  switch (extension) {
    case '.ts':
    case '.mts':
    case '.cts':
      return ts.ScriptKind.TS;
    case '.tsx':
      return ts.ScriptKind.TSX;
    case '.jsx':
      return ts.ScriptKind.JSX;
    default:
      return ts.ScriptKind.JS;
  }
}

function getExtension(filename: string): string {
  const dot = filename.lastIndexOf('.');
  return dot === -1 ? '' : filename.slice(dot).toLowerCase();
}

/**
 * Whether `arg` names the skill module's own directory: CommonJS
 * `__dirname`, ESM `import.meta.dirname`, any expression built from
 * `import.meta.url`/`import.meta.dirname`/`import.meta.filename` (e.g.
 * `path.dirname(fileURLToPath(import.meta.url))`), or a variable holding
 * one of those. The ESM forms used to be missed, so an ESM skill scoped
 * to its own directory was flagged as unscoped (PROPOSED_FIXES.md 2.6).
 */
function isModuleDirArgument(
  arg: ts.Expression | undefined,
  aliases: ReadonlySet<string>,
): boolean {
  if (arg === undefined) {
    return false;
  }
  if (ts.isIdentifier(arg)) {
    return arg.text === '__dirname' || aliases.has(arg.text);
  }
  return referencesImportMetaLocation(arg);
}

/** Variables initialized from the module's own location (`const here = path.dirname(fileURLToPath(import.meta.url))`). */
function collectModuleDirAliases(root: ts.Node): Set<string> {
  const aliases = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer !== undefined &&
      referencesImportMetaLocation(node.initializer)
    ) {
      aliases.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(root);
  return aliases;
}

const IMPORT_META_LOCATION_PROPERTIES = new Set(['url', 'dirname', 'filename']);

function referencesImportMetaLocation(node: ts.Node): boolean {
  if (
    ts.isPropertyAccessExpression(node) &&
    ts.isMetaProperty(node.expression) &&
    node.expression.keywordToken === ts.SyntaxKind.ImportKeyword &&
    IMPORT_META_LOCATION_PROPERTIES.has(node.name.text)
  ) {
    return true;
  }
  return (
    ts.forEachChild(node, (child) => referencesImportMetaLocation(child) || undefined) ?? false
  );
}

/**
 * Every name the file declares (variables, including destructured ones,
 * functions, classes, imports). A declared name shadows the global of the
 * same name, so `const Bun = {...}; Bun.spawn()` or a local `fetch` isn't
 * read as the runtime global. Flat scope like the rest of this module;
 * parameters aren't included, so a parameter named `fetch` doesn't hide
 * every global `fetch` call in the file.
 */
function collectDeclaredNames(root: ts.Node): Set<string> {
  const names = new Set<string>();
  const addBindingName = (name: ts.BindingName): void => {
    if (ts.isIdentifier(name)) {
      names.add(name.text);
      return;
    }
    for (const element of name.elements) {
      if (!ts.isOmittedExpression(element)) {
        addBindingName(element.name);
      }
    }
  };
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node)) {
      // `const fetch = globalThis.fetch` re-exposes the global; it doesn't shadow it.
      if (!(ts.isIdentifier(node.name) && isSameGlobalAlias(node.name.text, node.initializer))) {
        addBindingName(node.name);
      }
    } else if (
      (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) &&
      node.name !== undefined
    ) {
      names.add(node.name.text);
    } else if (ts.isImportClause(node) && node.name !== undefined) {
      names.add(node.name.text);
    } else if (ts.isNamespaceImport(node) || ts.isImportSpecifier(node)) {
      names.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(root);
  return names;
}

function isSameGlobalAlias(name: string, initializer: ts.Expression | undefined): boolean {
  if (initializer === undefined) {
    return false;
  }
  const member = getMemberAccess(unwrapParentheses(initializer));
  return (
    member !== null &&
    member.name === name &&
    ts.isIdentifier(member.object) &&
    GLOBAL_OBJECT_NAMES.has(member.object.text)
  );
}

function collectBindings(
  root: ts.Node,
  bindings: Map<string, Binding>,
  declared: ReadonlySet<string>,
  evalAliases: Set<string>,
): void {
  const declarations: ts.VariableDeclaration[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      collectImportBindings(node, normalizeModule(node.moduleSpecifier.text), bindings);
    }
    if (ts.isVariableDeclaration(node) && node.initializer) {
      declarations.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(root);

  // Variables bound to a module or a member of one: `require(...)`,
  // `require('fs').promises`, and aliases of an existing binding
  // (`const run = cp['exec']`). A few passes resolve an alias declared
  // before the binding it refers to, or an alias of an alias.
  for (let pass = 0; pass < 3; pass++) {
    let changed = false;
    for (const decl of declarations) {
      const initializer = unwrapParentheses(decl.initializer ?? decl);
      if (ts.isIdentifier(decl.name) && bindings.has(decl.name.text)) {
        continue;
      }
      if (
        ts.isIdentifier(decl.name) &&
        !evalAliases.has(decl.name.text) &&
        ts.isExpression(initializer) &&
        isEvalReference(initializer, declared, evalAliases)
      ) {
        evalAliases.add(decl.name.text);
        changed = true;
        continue;
      }
      const resolved = ts.isExpression(initializer)
        ? resolveModuleRef(initializer, bindings)
        : null;
      if (resolved !== null && addDeclarationBindings(decl.name, resolved, bindings)) {
        changed = true;
      }
    }
    if (!changed) {
      break;
    }
  }
}

function collectImportBindings(
  node: ts.ImportDeclaration,
  module: string,
  bindings: Map<string, Binding>,
): void {
  const clause = node.importClause;
  if (!clause) {
    return;
  }
  if (clause.name) {
    // Default import — treated like a namespace binding (`import axios
    // from 'axios'; axios(url)` is a real, common pattern).
    bindings.set(clause.name.text, { module, path: [] });
  }
  const namedBindings = clause.namedBindings;
  if (namedBindings && ts.isNamespaceImport(namedBindings)) {
    bindings.set(namedBindings.name.text, { module, path: [] });
  } else if (namedBindings && ts.isNamedImports(namedBindings)) {
    for (const specifier of namedBindings.elements) {
      const original = (specifier.propertyName ?? specifier.name).text;
      // `import { default as x }` is the module itself.
      bindings.set(specifier.name.text, { module, path: original === 'default' ? [] : [original] });
    }
  }
}

/** Binds a declaration's name (or each destructured name) to `resolved`; returns whether anything was added. */
function addDeclarationBindings(
  name: ts.BindingName,
  resolved: Binding,
  bindings: Map<string, Binding>,
): boolean {
  if (ts.isIdentifier(name)) {
    bindings.set(name.text, resolved);
    return true;
  }
  let added = false;
  if (ts.isObjectBindingPattern(name)) {
    for (const element of name.elements) {
      if (!ts.isIdentifier(element.name) || bindings.has(element.name.text)) {
        continue;
      }
      const original =
        element.propertyName && ts.isIdentifier(element.propertyName)
          ? element.propertyName.text
          : element.name.text;
      bindings.set(element.name.text, {
        module: resolved.module,
        path: [...resolved.path, original],
      });
      added = true;
    }
  }
  return added;
}

/**
 * Resolves an expression to the module member it refers to:
 * `require('x')`, a bound identifier, or a property/element access on
 * either (`cp.exec`, `cp['exec']`, ``cp[`exec`]``, `fs.promises.writeFile`).
 */
function resolveModuleRef(
  expr: ts.Expression,
  bindings: ReadonlyMap<string, Binding>,
): Binding | null {
  const inner = unwrapParentheses(expr);
  if (ts.isIdentifier(inner)) {
    return bindings.get(inner.text) ?? null;
  }
  const required = unwrapRequireCall(inner);
  if (required !== null) {
    return { module: normalizeModule(required), path: [] };
  }
  const member = getMemberAccess(inner);
  if (member !== null) {
    const base = resolveModuleRef(member.object, bindings);
    return base === null ? null : { module: base.module, path: [...base.path, member.name] };
  }
  return null;
}

/** `obj.name`, `obj['name']`, or ``obj[`name`]`` as `{object, name}`; null for computed keys. */
function getMemberAccess(expr: ts.Expression): { object: ts.Expression; name: string } | null {
  if (ts.isPropertyAccessExpression(expr)) {
    return { object: expr.expression, name: expr.name.text };
  }
  if (ts.isElementAccessExpression(expr) && ts.isStringLiteralLike(expr.argumentExpression)) {
    return { object: expr.expression, name: expr.argumentExpression.text };
  }
  return null;
}

function unwrapParentheses<T extends ts.Node>(node: T): T | ts.Expression {
  let current: ts.Node = node;
  while (ts.isParenthesizedExpression(current)) {
    current = current.expression;
  }
  return current as T | ts.Expression;
}

function normalizeModule(specifier: string): string {
  return specifier.startsWith('node:') ? specifier.slice('node:'.length) : specifier;
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
  return arg !== undefined && ts.isStringLiteralLike(arg) ? arg.text : null;
}

function resolveCallTarget(
  callee: ts.Expression,
  bindings: ReadonlyMap<string, Binding>,
): CallTarget | null {
  const resolved = resolveModuleRef(callee, bindings);
  if (resolved === null) {
    return null;
  }
  return { module: resolved.module, functionName: resolved.path.at(-1) ?? '', path: resolved.path };
}

function getCalleeSimpleName(callee: ts.Expression): string | null {
  if (ts.isIdentifier(callee)) {
    return callee.text;
  }
  return getMemberAccess(callee)?.name ?? null;
}

function isGenericMemberVerbCall(callee: ts.Expression, calleeName: string): boolean {
  const isMemberCall =
    ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee);
  return isMemberCall && GENERIC_MEMBER_VERBS.has(calleeName.toLowerCase());
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
