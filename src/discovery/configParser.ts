import YAML from 'yaml';
import type { JsonValue, SecretField } from '../model/types.js';
import { isRecord } from './jsonUtils.js';
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
  const trimmed = value.trim();
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

export type LineLookup = (keyPath: string) => number | null;

const NO_LINE_LOOKUP: LineLookup = () => null;

/**
 * Builds a `keyPath -> source line` lookup for a config (improvement_plan.md
 * 1.17), using `YAML.parseDocument`'s CST (which retains source ranges) —
 * distinct from `parseConfigSource`'s plain-value parse, which discards
 * position info entirely. JSON has no equivalent free CST-with-positions
 * in this codebase's chosen parser (`JSON.parse`), so a JSON config gets
 * a lookup that always returns `null` — a documented limitation, not a
 * silent inconsistency (see `SecretField.line`'s doc comment).
 */
export function createLineLookup(source: string, format: 'yaml' | 'json'): LineLookup {
  if (format === 'json') {
    return NO_LINE_LOOKUP;
  }

  const lineCounter = new YAML.LineCounter();
  let doc: ReturnType<typeof YAML.parseDocument>;
  try {
    doc = YAML.parseDocument(source, { lineCounter });
  } catch {
    return NO_LINE_LOOKUP;
  }

  return (keyPath: string): number | null => {
    const segments = parseKeyPathSegments(keyPath);
    if (segments.length === 0) {
      return null;
    }
    try {
      const node: unknown = doc.getIn(segments, true);
      if (isRangedNode(node)) {
        return lineCounter.linePos(node.range[0]).line;
      }
    } catch {
      // keyPath didn't resolve to a real node in the document — no line info.
    }
    return null;
  };
}

function isRangedNode(value: unknown): value is { range: [number, number, number] } {
  if (!isRecord(value)) {
    return false;
  }
  const range = value['range'];
  return Array.isArray(range) && typeof range[0] === 'number';
}

/** Splits a masking keyPath like `trust.tool_allowlist[0]` back into the segments `YAML.Document#getIn` expects: `['trust', 'tool_allowlist', 0]`. */
function parseKeyPathSegments(keyPath: string): Array<string | number> {
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

/** Parses raw config source text (YAML or JSON) into an untyped value tree. Secrets are NOT masked yet. */
export function parseConfigSource(source: string, format: 'yaml' | 'json'): unknown {
  return format === 'json' ? (JSON.parse(source) as unknown) : (YAML.parse(source) as unknown);
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
      if (typeof value === 'string' && value.length > 0 && looksLikeSecretKeyName(key)) {
        const isEnvRef = looksLikeEnvReference(value);
        const displayValue = isEnvRef ? value : maskSecretValue(value);
        result[key] = displayValue;
        out.push({ keyPath: childPath, displayValue, looksLikeEnvReference: isEnvRef, line: null });
        continue;
      }
      result[key] = maskTree(value, childPath, out);
    }
    return result;
  }
  return node;
}
