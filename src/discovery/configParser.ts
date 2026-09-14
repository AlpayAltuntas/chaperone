import YAML from 'yaml';
import type { JsonValue, SecretField } from '../model/types.js';
import { isRecord } from './jsonUtils.js';

const SECRET_KEY_PATTERN = /(api[_-]?key|token|secret|password|passwd|credential)/i;

// Conventions for "this value is an indirect reference, not the literal
// secret": `${VAR}` / `$VAR` interpolation syntax, and an `env:VAR` prefix.
const ENV_REF_PATTERNS = [/^\$\{[A-Za-z0-9_]+\}$/, /^env:[A-Za-z0-9_]+$/i, /^\$[A-Za-z0-9_]+$/];

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
      if (typeof value === 'string' && value.length > 0 && SECRET_KEY_PATTERN.test(key)) {
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
