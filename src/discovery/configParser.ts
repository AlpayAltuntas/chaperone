import YAML from 'yaml';
import type { JsonValue, SecretField } from '../model/types.js';
import { isRecord } from './jsonUtils.js';
import { detectSecretValue } from './secretValuePatterns.js';
import { splitWordSegments } from './wordSegments.js';

// Whole-word segments (after splitting a key on `_`/`-`/camelCase
// boundaries) that mark a field as secret-shaped. Matching whole segments
// rather than a substring avoids two opposite bugs a naive substring
// regex had: false negatives on snake_case names like `private_key`/
// `ssh_key`/`encryption_key` (only the literal sequence "api_key" was
// ever recognized — a bare "key" segment wasn't matched at all), and
// false positives on words that merely *contain* one of these terms,
// like `tokenizer_model` or `keyboard_layout`.
const SECRET_KEY_SEGMENTS = new Set([
  'key',
  'apikey',
  'token',
  'secret',
  'secrets',
  'password',
  'passwd',
  'credential',
  'credentials',
]);

export function looksLikeSecretKeyName(key: string): boolean {
  return splitWordSegments(key).some((segment) => SECRET_KEY_SEGMENTS.has(segment));
}

// Weaker signals (PROPOSED_FIXES.md 3.1): `auth`, `authorization`,
// `cookie`, and friends often hold a credential, but just as often a
// mode or a setting (`auth: none`, `session_timeout: 30m`, `auth_type:
// bearer`). They count only as the key's LAST segment, and only for a
// value that looks like a credential rather than a word or a setting:
// at least 8 characters, no whitespace, and both a letter and a digit.
const WEAK_SECRET_KEY_LAST_SEGMENTS = new Set([
  'auth',
  'authorization',
  'bearer',
  'cookie',
  'session',
]);

function looksLikeWeakSecretKey(key: string, value: string): boolean {
  const last = splitWordSegments(key).at(-1);
  if (last === undefined || !WEAK_SECRET_KEY_LAST_SEGMENTS.has(last)) {
    return false;
  }
  const trimmed = value.trim();
  return (
    trimmed.length >= 8 && !/\s/.test(trimmed) && /[A-Za-z]/.test(trimmed) && /\d/.test(trimmed)
  );
}

// Conventions for "this value is an indirect reference, not the literal
// secret": `${VAR}` / `$VAR` interpolation syntax, an `env:VAR` prefix, and
// bash/docker-compose-style parameter expansion with a default or error
// fallback (`${VAR:-default}` / `${VAR:=default}` / `${VAR:?message}` /
// `${VAR:+alt}`) — common in real config templating and not previously
// recognized, which meant a value using that (safe) style was masked and
// flagged as if it were a literal secret.
const ENV_REF_PATTERNS = [
  /^\$\{[A-Za-z0-9_]+(:[-=?+][^}]*)?\}$/,
  /^env:[A-Za-z0-9_]+$/i,
  /^\$[A-Za-z0-9_]+$/,
];

export function looksLikeEnvReference(value: string): boolean {
  // `Bearer ${TOKEN}` (an Authorization header built from an env var) is
  // as indirect as `${TOKEN}` itself.
  const trimmed = value.trim().replace(/^(?:Bearer|Basic|Token)\s+/i, '');
  return ENV_REF_PATTERNS.some((re) => re.test(trimmed));
}

// Bare-reference forms only (no `:-`/`:=`/`:?`/`:+` fallback/default) —
// those modifiers mean the reference resolves to *something* even when
// the variable itself is unset, so CHAP-SEC-007 (which asks "is the var
// actually set?") deliberately can't say anything useful about them and
// skips them rather than risk a false positive.
const BARE_ENV_REF_PATTERNS = [
  /^\$\{([A-Za-z0-9_]+)\}$/,
  /^env:([A-Za-z0-9_]+)$/i,
  /^\$([A-Za-z0-9_]+)$/,
];

/** Extracts the variable name from a bare `${VAR}`/`$VAR`/`env:VAR` reference, or null if it's not one of those forms. */
export function extractEnvVarName(value: string): string | null {
  const trimmed = value.trim();
  for (const re of BARE_ENV_REF_PATTERNS) {
    const match = re.exec(trimmed);
    if (match?.[1] !== undefined) {
      return match[1];
    }
  }
  return null;
}

/**
 * Maps every key path in a config (`trust.tool_allowlist`,
 * `trust.tool_allowlist[1]`, the same form maskConfig uses) to its
 * 1-indexed source line, using `YAML.parseDocument`'s source ranges
 * (improvement_plan.md 1.17). JSON is valid YAML 1.2, so the same parser
 * gives JSON configs line numbers too (PROPOSED_FIXES.md 4.2); values
 * are still taken from `JSON.parse`, only positions come from here.
 * Returns an empty index for unparseable input, never throws.
 */
export function buildKeyLineIndex(
  source: string,
  format: 'yaml' | 'json' = 'yaml',
): Record<string, number> {
  const lineCounter = new YAML.LineCounter();
  let doc: ReturnType<typeof YAML.parseDocument>;
  try {
    doc = YAML.parseDocument(format === 'json' ? blankJson5(source) : source, {
      lineCounter,
      uniqueKeys: false,
    });
  } catch {
    return {};
  }
  const index: Record<string, number> = {};
  const lineOf = (node: unknown): number | null =>
    isRangedNode(node) ? lineCounter.linePos(node.range[0]).line : null;
  const walk = (node: unknown, prefix: string): void => {
    if (YAML.isMap(node)) {
      for (const pair of node.items) {
        if (!YAML.isScalar(pair.key)) {
          continue;
        }
        const keyPath = prefix ? `${prefix}.${String(pair.key.value)}` : String(pair.key.value);
        const line = lineOf(pair.key);
        if (line !== null) {
          index[keyPath] = line;
        }
        walk(pair.value, keyPath);
      }
    } else if (YAML.isSeq(node)) {
      node.items.forEach((item, i) => {
        const keyPath = `${prefix}[${String(i)}]`;
        const line = lineOf(item);
        if (line !== null) {
          index[keyPath] = line;
        }
        walk(item, keyPath);
      });
    }
  };
  try {
    walk(doc.contents, '');
  } catch {
    return {};
  }
  return index;
}

function isRangedNode(value: unknown): value is { range: [number, number, number] } {
  if (!isRecord(value)) {
    return false;
  }
  const range = value['range'];
  return Array.isArray(range) && typeof range[0] === 'number';
}

/**
 * Splits a masking keyPath like `trust.tool_allowlist[0]` back into the
 * segments `YAML.Document#getIn`/`#setIn` expects: `['trust',
 * 'tool_allowlist', 0]`. Exported for src/fix/ (improvement_plan.md
 * 3.14/Phase 22) — guided remediation reuses this exact parse to locate
 * the field it's about to edit.
 */
export function parseKeyPathSegments(keyPath: string): Array<string | number> {
  const segments: Array<string | number> = [];
  const pattern = /([^.[\]]+)|\[(\d+)\]/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(keyPath)) !== null) {
    if (match[1] !== undefined) {
      segments.push(match[1]);
    } else if (match[2] !== undefined) {
      segments.push(Number(match[2]));
    }
  }
  return segments;
}

export function maskSecretValue(value: string): string {
  if (value.length <= 8) {
    return '*'.repeat(Math.max(value.length, 3));
  }
  return `${value.slice(0, 3)}…${value.slice(-4)}`;
}

/** Parses raw config source text (YAML, or JSON/JSON5) into an untyped value tree. Secrets are NOT masked yet. */
export function parseConfigSource(source: string, format: 'yaml' | 'json'): unknown {
  if (format === 'yaml') {
    return YAML.parse(source) as unknown;
  }
  try {
    return JSON.parse(source) as unknown;
  } catch {
    // JSON5 (OpenClaw's openclaw.json): comments and trailing commas
    // blanked, then YAML 1.2's flow syntax handles unquoted keys and
    // single-quoted strings (PROPOSED_FIXES.md 6.2).
    return YAML.parse(blankJson5(source)) as unknown;
  }
}

/**
 * Replaces JSON5 comments and trailing commas with spaces (newlines kept),
 * so the result has the same length and line structure as the input and
 * parses as YAML flow syntax. Offsets found in the result are valid in
 * the original, which is what lets fixers edit a JSON5 file in place.
 * Plain JSON passes through unchanged.
 */
export function blankJson5(source: string): string {
  const out = source.split('');
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (ch === '"' || ch === "'") {
      i++;
      while (i < source.length && source[i] !== ch) {
        i += source[i] === '\\' ? 2 : 1;
      }
      i++;
      continue;
    }
    if (ch === '/' && source[i + 1] === '/') {
      while (i < source.length && source[i] !== '\n') {
        out[i++] = ' ';
      }
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      const end = source.indexOf('*/', i + 2);
      const stop = end === -1 ? source.length : end + 2;
      for (; i < stop; i++) {
        if (source[i] !== '\n') {
          out[i] = ' ';
        }
      }
      continue;
    }
    if (ch === ',') {
      let j = i + 1;
      while (j < source.length && /\s/.test(out[j] ?? '')) {
        j++;
      }
      if (out[j] === '}' || out[j] === ']') {
        out[i] = ' ';
      }
    }
    i++;
  }
  return out.join('');
}

export interface MaskConfigResult {
  data: JsonValue | null;
  secretFields: SecretField[];
}

/**
 * Walks a parsed config tree, replacing literal secret-looking values with a
 * masked display form and collecting their locations. Values that are
 * already indirect references (env vars) are left visible since they carry
 * no sensitive material. The real literal values never leave this function.
 */
export function maskConfig(rawParsed: unknown): MaskConfigResult {
  if (!isRecord(rawParsed) && !Array.isArray(rawParsed)) {
    return { data: null, secretFields: [] };
  }
  const secretFields: SecretField[] = [];
  const data = maskTree(rawParsed as JsonValue, '', secretFields);
  return { data, secretFields };
}

function maskTree(node: JsonValue, keyPath: string, out: SecretField[]): JsonValue {
  if (Array.isArray(node)) {
    return node.map((item, index) => maskTree(item, `${keyPath}[${index}]`, out));
  }
  if (isRecord(node)) {
    const result: Record<string, JsonValue> = {};
    for (const [key, value] of Object.entries(node)) {
      const childPath = keyPath ? `${keyPath}.${key}` : key;
      if (
        typeof value === 'string' &&
        value.length > 0 &&
        (looksLikeSecretKeyName(key) || looksLikeWeakSecretKey(key, value))
      ) {
        const isEnvRef = looksLikeEnvReference(value);
        const valueMatch = isEnvRef ? null : detectSecretValue(value, maskSecretValue);
        const displayValue = isEnvRef ? value : maskSecretValue(value);
        result[key] = displayValue;
        out.push({
          keyPath: childPath,
          displayValue,
          looksLikeEnvReference: isEnvRef,
          line: null,
          detectedBy: 'key-name',
          pattern: valueMatch?.pattern ?? null,
        });
        continue;
      }
      result[key] = maskTree(value, childPath, out);
    }
    return result;
  }
  if (typeof node === 'string' && keyPath !== '') {
    // A secret under an innocuous key name (`headers.Authorization`,
    // `base_url`, an MCP server's args) is caught by its value instead,
    // and masked here so the literal never reaches the model.
    const valueMatch = detectSecretValue(node, maskSecretValue);
    if (valueMatch !== null) {
      out.push({
        keyPath,
        displayValue: valueMatch.masked,
        looksLikeEnvReference: false,
        line: null,
        detectedBy: 'value-pattern',
        pattern: valueMatch.pattern,
      });
      return valueMatch.masked;
    }
  }
  return node;
}
