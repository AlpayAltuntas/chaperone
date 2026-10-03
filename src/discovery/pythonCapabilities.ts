import type { CapabilityEvidence } from '../model/types.js';
import type { DetectedCapabilities } from './astCapabilities.js';
import { splitWordSegments } from './wordSegments.js';

// Python capability detection (improvement_plan.md 1.9/Phase 16),
// still pattern-based rather than a real parser (no Python tokenizer
// dependency exists in this project; see DECISIONS.md, Phase 16), but
// with three improvements from PROPOSED_FIXES.md 3.4:
//
// - Comments and string contents are blanked out before matching, so a
//   keyword in a docstring or a comment no longer counts.
// - An import-alias table (`import subprocess as sp`, `from subprocess
//   import run`, `from os import system as sh`) resolves each call back
//   to its qualified name before it's matched.
// - Calls are matched by qualified name, so `cursor.exec(...)` is no
//   longer mistaken for the `exec` builtin.
//
// Known gaps (documented, not solved): no scope or data-flow tracking, a
// call through a variable holding a function isn't resolved, and string
// blanking is a small tokenizer, not a full one (f-string nesting is
// approximate).

const SHELL_EXEC_CALLS = new Set([
  'subprocess.run',
  'subprocess.call',
  'subprocess.check_call',
  'subprocess.check_output',
  'subprocess.Popen',
  'subprocess.getoutput',
  'subprocess.getstatusoutput',
  'os.system',
  'os.popen',
  'os.execv',
  'os.execve',
  'os.execl',
  'os.execle',
  'os.execlp',
  'os.execvp',
  'os.execvpe',
  'os.spawnv',
  'os.spawnl',
  'os.spawnlp',
  'os.spawnvp',
  'os.posix_spawn',
  'os.posix_spawnp',
  'asyncio.create_subprocess_shell',
  'asyncio.create_subprocess_exec',
  'pty.spawn',
]);

const FS_WRITE_CALLS = new Set([
  'os.remove',
  'os.unlink',
  'os.rmdir',
  'os.removedirs',
  'os.rename',
  'os.replace',
  'os.chmod',
  'os.chown',
  'os.truncate',
  'shutil.rmtree',
  'shutil.move',
  'shutil.copy',
  'shutil.copy2',
  'shutil.copyfile',
  'shutil.copytree',
]);
// `open(path, "w")` and friends: matched on the comment-free source, since
// the mode is a string.
const OPEN_FOR_WRITE = /(?<![\w.])open\([^\n]*,\s*(?:mode\s*=\s*)?['"][rb+]*[wxa][bt+]*['"]/g;

// Any call into these modules is network access.
const NETWORK_MODULES = new Set([
  'requests',
  'httpx',
  'aiohttp',
  'urllib3',
  'urllib.request',
  'http.client',
  'websockets',
  'smtplib',
  'ftplib',
  'paramiko',
]);
const NETWORK_CALLS = new Set(['socket.socket', 'socket.create_connection']);

// Dynamic code: the eval/exec builtins, a computed import, and
// deserializers that execute code embedded in the data.
const DYNAMIC_EVAL_CALLS = new Set([
  'eval',
  'exec',
  '__import__',
  'importlib.import_module',
  'pickle.loads',
  'pickle.load',
  'cPickle.loads',
  'cPickle.load',
  'dill.loads',
  'dill.load',
  'marshal.loads',
  'marshal.load',
  'yaml.unsafe_load',
  'yaml.full_load',
]);
// `yaml.load(data)` is unsafe unless given a safe loader.
const YAML_SAFE_LOADER = /Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader|BaseLoader)\b/;

// Evidence that file access is scoped to a fixed base directory rather
// than an arbitrary caller-supplied path — the same proxy signal
// astCapabilities.ts uses for JS/TS (CHAP-AGY-002).
const FS_SCOPING_PATTERNS = [
  /os\.path\.(?:join|abspath)\(\s*os\.path\.dirname\(__file__\)/,
  /Path\(__file__\)/,
  /\b\w*(?:WORKSPACE|SANDBOX|SCOPED)\w*\s*=/i,
];

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

// A dotted name followed by `(`, not preceded by another name character
// or a dot (so `cursor.exec(` is matched as `cursor.exec`, never `exec`).
const CALL = /(?<![\w.])([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\(/g;

/**
 * Python capability detection. `dataFlowToShellExec` is always `false`;
 * porting CHAP-INJ-002's taint analysis to a second language is out of
 * scope.
 */
export function detectPythonCapabilities(source: string, file = '<python>'): DetectedCapabilities {
  const { withoutComments, code } = blankCommentsAndStrings(source);
  const aliases = collectImportAliases(code);
  const evidence: CapabilityEvidence[] = [];
  const scoped = FS_SCOPING_PATTERNS.some((re) => re.test(withoutComments));

  const record = (
    capability: CapabilityEvidence['capability'],
    index: number,
    api: string,
  ): void => {
    evidence.push({
      capability,
      file,
      line: lineOf(source, index),
      api,
      ...(capability === 'fileSystemAccess' ? { scoped } : {}),
    });
  };

  for (const match of code.matchAll(CALL)) {
    const written = (match[1] ?? '').replace(/\s+/g, '');
    if (isDefinition(code, match.index)) {
      continue;
    }
    const qualified = resolveAlias(written, aliases);
    if (SHELL_EXEC_CALLS.has(qualified)) {
      record('shellExec', match.index, qualified);
    }
    if (FS_WRITE_CALLS.has(qualified)) {
      record('fileSystemAccess', match.index, qualified);
    }
    if (NETWORK_CALLS.has(qualified) || isInModule(qualified, NETWORK_MODULES)) {
      record('networkAccess', match.index, qualified);
    }
    if (DYNAMIC_EVAL_CALLS.has(qualified)) {
      record('dynamicEval', match.index, qualified);
    }
    if (
      qualified === 'yaml.load' &&
      !YAML_SAFE_LOADER.test(callText(withoutComments, match.index))
    ) {
      record('dynamicEval', match.index, 'yaml.load (no SafeLoader)');
    }
  }
  // Method calls on any receiver (`Path(p).write_text(...)`), which the
  // CALL pattern skips because they follow a dot.
  for (const match of code.matchAll(/\.\s*(write_text|write_bytes)\s*\(/g)) {
    record('fileSystemAccess', match.index, `.${match[1] ?? ''}`);
  }
  for (const match of withoutComments.matchAll(OPEN_FOR_WRITE)) {
    record('fileSystemAccess', match.index, 'open (write mode)');
  }

  const destructiveKeywords = new Set<string>();
  for (const match of code.matchAll(MODULE_LEVEL_DEF)) {
    const name = match[1] ?? '';
    const keywords = splitWordSegments(name).filter((segment) => DESTRUCTIVE_KEYWORDS.has(segment));
    if (keywords.length > 0) {
      keywords.forEach((keyword) => destructiveKeywords.add(keyword));
      record('destructive', match.index, name);
    }
  }

  evidence.sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
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

/** `def name(` / `class Name(` at this position: a definition, not a call. */
function isDefinition(code: string, index: number): boolean {
  return /(?:^|[^\w])(?:def|class)\s+$/.test(code.slice(Math.max(0, index - 12), index));
}

function isInModule(qualified: string, modules: ReadonlySet<string>): boolean {
  for (const module of modules) {
    if (qualified === module || qualified.startsWith(`${module}.`)) {
      return true;
    }
  }
  return false;
}

/** The text of a call from its name to the end of the line, for argument checks. */
function callText(text: string, index: number): string {
  const end = text.indexOf('\n', index);
  return text.slice(index, end === -1 ? undefined : end);
}

/**
 * Local name -> qualified name, from `import a.b as c`, `import a, b`,
 * and `from m import x as y, z` (including a parenthesized, multi-line
 * name list).
 */
export function collectImportAliases(code: string): Map<string, string> {
  const aliases = new Map<string, string>();
  for (const match of code.matchAll(/^[ \t]*import[ \t]+([^\n]+)/gm)) {
    for (const part of (match[1] ?? '').split(',')) {
      const [module, alias] = part.trim().split(/\s+as\s+/);
      if (module === undefined || module === '') {
        continue;
      }
      if (alias !== undefined) {
        aliases.set(alias.trim(), module.trim());
      }
    }
  }
  for (const match of code.matchAll(
    /^[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]+(\([^)]*\)|[^\n]+)/gm,
  )) {
    const module = match[1] ?? '';
    const names = (match[2] ?? '').replace(/[()\\]/g, ' ');
    for (const part of names.split(',')) {
      const [name, alias] = part.trim().split(/\s+as\s+/);
      if (name === undefined || name === '' || name === '*') {
        continue;
      }
      aliases.set((alias ?? name).trim(), `${module}.${name.trim()}`);
    }
  }
  return aliases;
}

function resolveAlias(written: string, aliases: ReadonlyMap<string, string>): string {
  const dot = written.indexOf('.');
  const head = dot === -1 ? written : written.slice(0, dot);
  const target = aliases.get(head);
  if (target === undefined) {
    return written;
  }
  return dot === -1 ? target : `${target}${written.slice(dot)}`;
}

/**
 * Two copies of the source with the same length and line structure:
 * `withoutComments` has `#` comments blanked; `code` additionally blanks
 * the contents of every string literal (single, double, and triple
 * quoted, with any prefix). Blanked characters become spaces so match
 * offsets still map to the original lines.
 */
export function blankCommentsAndStrings(source: string): { withoutComments: string; code: string } {
  const withoutComments = source.split('');
  const code = source.split('');
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') {
        withoutComments[i] = ' ';
        code[i] = ' ';
        i++;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      const triple = source.startsWith(ch.repeat(3), i);
      const quote = triple ? ch.repeat(3) : ch;
      let j = i + quote.length;
      while (j < source.length && !source.startsWith(quote, j)) {
        if (source[j] === '\\') {
          j += 2;
          continue;
        }
        if (!triple && source[j] === '\n') {
          break;
        }
        j++;
      }
      for (let k = i + quote.length; k < Math.min(j, source.length); k++) {
        if (source[k] !== '\n') {
          code[k] = ' ';
        }
      }
      i = Math.min(j + quote.length, source.length);
      continue;
    }
    i++;
  }
  return { withoutComments: withoutComments.join(''), code: code.join('') };
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
