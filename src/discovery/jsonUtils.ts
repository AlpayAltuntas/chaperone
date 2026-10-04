import { splitWordSegments } from './wordSegments.js';

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Reads a config key by its canonical snake_case name, also accepting
 * the camelCase and kebab-case spellings of the same key
 * (`auto_execute_links`, `autoExecuteLinks`, `auto-execute-links`).
 * JSON configs are conventionally camelCase, and reading only snake_case
 * silently turned set keys into "missing" (PROPOSED_FIXES.md 2.3). An
 * exact match wins when several spellings are present.
 */
export function getConfigField(record: Record<string, unknown>, snakeName: string): unknown {
  const key = findConfigKey(record, snakeName);
  return key === undefined ? undefined : record[key];
}

/** The key actually used in `record` for `snakeName`, in any accepted spelling (see getConfigField). */
export function findConfigKey(
  record: Record<string, unknown>,
  snakeName: string,
): string | undefined {
  if (snakeName in record) {
    return snakeName;
  }
  return Object.keys(record).find((key) => splitWordSegments(key).join('_') === snakeName);
}
