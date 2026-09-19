import { readFileSync } from 'node:fs';
import YAML from 'yaml';
import { parseKeyPathSegments } from '../discovery/configParser.js';
import { suggestEnvVarName } from './envVarName.js';
import type { FixChange, FixPlan, Fixer } from './types.js';

/**
 * CHAP-SEC-001's fixer (improvement_plan.md 3.14/Phase 22's DoD example
 * check) — replaces every literal (non-env-reference) secret value
 * `model.config.secretFields` already found with a `${SUGGESTED_NAME}`
 * env-var reference, preserving the config file's own formatting via
 * `YAML.Document#setIn` (a round-trip-preserving edit, not a
 * parse-and-regenerate-from-scratch one) for YAML, or a plain
 * `JSON.parse`/`stringify` round-trip for JSON (which has no comments to
 * preserve anyway).
 *
 * Never reads or re-derives the real secret value for anything — the
 * proposed change only ever needs the field's *keyPath* (to locate and
 * overwrite it) and its already-masked `displayValue` (to show what's
 * changing), both already sitting on the AgentModel. `plan()` re-reads
 * the config file's raw text once, purely to get a fresh parse to edit
 * — the same file `discoverAgent` already read, never written to.
 */
export const chapSec001Fixer: Fixer = {
  checkId: 'CHAP-SEC-001',
  plan(model): FixPlan | null {
    const { path: filePath, format } = model.config;
    if (filePath === null || format === null) {
      return null;
    }

    const literalFields = model.config.secretFields.filter((field) => !field.looksLikeEnvReference);
    if (literalFields.length === 0) {
      return null;
    }

    const raw = readFileSync(filePath, 'utf8');
    const changes: FixChange[] = [];

    if (format === 'yaml') {
      const doc = YAML.parseDocument(raw);
      for (const field of literalFields) {
        const newValue = `\${${suggestEnvVarName(field.keyPath)}}`;
        doc.setIn(parseKeyPathSegments(field.keyPath), newValue);
        changes.push({ keyPath: field.keyPath, oldDisplayValue: field.displayValue, newValue });
      }
      return { checkId: 'CHAP-SEC-001', filePath, changes, newContent: doc.toString() };
    }

    // JSON: no comments/formatting to preserve, so a plain parse/set/
    // re-stringify round-trip is fine — the same reasoning
    // configParser.ts's own maskConfig already applies.
    const parsed: unknown = JSON.parse(raw);
    for (const field of literalFields) {
      const newValue = `\${${suggestEnvVarName(field.keyPath)}}`;
      setInPlainObject(parsed, parseKeyPathSegments(field.keyPath), newValue);
      changes.push({ keyPath: field.keyPath, oldDisplayValue: field.displayValue, newValue });
    }
    return {
      checkId: 'CHAP-SEC-001',
      filePath,
      changes,
      newContent: `${JSON.stringify(parsed, null, 2)}\n`,
    };
  },
};

function setInPlainObject(
  root: unknown,
  segments: readonly (string | number)[],
  value: unknown,
): void {
  let cursor: unknown = root;
  for (let i = 0; i < segments.length - 1; i++) {
    if (typeof cursor !== 'object' || cursor === null) {
      return;
    }
    cursor = (cursor as Record<string | number, unknown>)[segments[i] as string | number];
  }
  const lastSegment = segments[segments.length - 1];
  if (typeof cursor === 'object' && cursor !== null && lastSegment !== undefined) {
    (cursor as Record<string | number, unknown>)[lastSegment] = value;
  }
}
