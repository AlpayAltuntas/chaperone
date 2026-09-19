import YAML from 'yaml';
import type { JsonValue, SecretField } from '../model/types.js';
import { isRecord } from './jsonUtils.js';

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

/** Splits a config key into lowercase segments on `_`, `-`, and camelCase boundaries, e.g. `apiKey` / `api_key` / `API_KEY` -> ['api', 'key']. */
function keySegments(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .split(/[_-]+/)
    .map((segment) => segment.toLowerCase())
    .filter((segment) => segment.length > 0);
}

export function looksLikeSecretKeyName(key: string): boolean {
  return keySegments(key).some((segment) => SECRET_KEY_SEGMENTS.has(segment));
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
        out.push({ keyPath: childPath, displayValue, looksLikeEnvReference: isEnvRef });
        continue;
      }
      result[key] = maskTree(value, childPath, out);
    }
    return result;
  }
  return node;
}
