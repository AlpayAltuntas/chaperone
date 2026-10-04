import { readFileSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { parseKeyPathSegments } from '../discovery/configParser.js';
import { setConfigValues } from './configEdit.js';
import { suggestEnvVarName } from './envVarName.js';
import { gitignoreAction } from './gitignore.js';
import type { FixAction, FixChange, FixPlan, Fixer } from './types.js';

/**
 * CHAP-SEC-001's fixer — replaces every literal secret value
 * `model.config.secretFields` found with a `${SUGGESTED_NAME}` env-var
 * reference. YAML keeps its comments and layout; JSON is edited in place,
 * so key order and indentation survive (PROPOSED_FIXES.md 5).
 *
 * Without `--write-env`, the real values are never read, only the
 * fields' key paths and masked display values from the model. With it,
 * the fixer reads each real value once from the config and writes it to
 * `.env` in the install root (created 0600, and added to the repository's
 * `.gitignore` when there is one), so confirming the fix can't lose a key
 * that isn't stored anywhere else. Real values are never printed.
 */
export const chapSec001Fixer: Fixer = {
  checkId: 'CHAP-SEC-001',
  plan(model, options = {}): FixPlan | null {
    const { path: filePath, format } = model.config;
    if (filePath === null || format === null) {
      return null;
    }
    const literalFields = model.config.secretFields.filter((field) => !field.looksLikeEnvReference);
    if (literalFields.length === 0) {
      return null;
    }

    const raw = readFileSync(filePath, 'utf8');
    const changes: FixChange[] = literalFields.map((field) => ({
      keyPath: field.keyPath,
      oldDisplayValue: field.displayValue,
      newValue: `\${${suggestEnvVarName(field.keyPath)}}`,
    }));
    const actions: FixAction[] = [
      {
        kind: 'write-file',
        filePath,
        content: setConfigValues(
          raw,
          format,
          changes.map((change) => ({ keyPath: change.keyPath, value: change.newValue })),
        ),
      },
    ];
    const names = literalFields.map((field) => suggestEnvVarName(field.keyPath));

    if (options.writeEnv === true) {
      const parsed: unknown = format === 'json' ? JSON.parse(raw) : YAML.parse(raw);
      const envPath = path.join(model.targetRoot, '.env');
      const lines = literalFields.flatMap((field) => {
        const value = valueAt(parsed, field.keyPath);
        return typeof value === 'string'
          ? [`${suggestEnvVarName(field.keyPath)}=${quoteEnv(value)}`]
          : [];
      });
      actions.push({ kind: 'append-lines', filePath: envPath, lines, mode: 0o600 });
      changes.push({
        keyPath: envPath,
        oldDisplayValue: '(values from the config)',
        newValue: `${String(lines.length)} variable${lines.length === 1 ? '' : 's'}, file mode 600`,
      });
      const ignore = gitignoreAction(model, envPath, false);
      if (ignore !== null) {
        actions.push(ignore.action);
        changes.push(ignore.change);
      }
    }

    const notes = [
      options.writeEnv === true
        ? `The values were moved to .env; make sure the agent loads it, or export: ${names.join(', ')}.`
        : `Before applying, store each value somewhere the agent can read it and export: ${names.join(', ')}. (--write-env moves them into a 0600 .env file for you.)`,
    ];
    if (model.git.hasAncestorGitDir) {
      notes.push(
        'This config is inside a git repository: if it was ever committed with these values, rotate the credentials. Removing them now does not remove them from history.',
      );
    }
    return { checkId: 'CHAP-SEC-001', changes, actions, notes };
  },
};

function valueAt(root: unknown, keyPath: string): unknown {
  let cursor: unknown = root;
  for (const segment of parseKeyPathSegments(keyPath)) {
    if (typeof cursor !== 'object' || cursor === null) {
      return undefined;
    }
    cursor = (cursor as Record<string | number, unknown>)[segment];
  }
  return cursor;
}

/** Double-quotes a .env value when it holds anything a dotenv parser would treat specially. */
function quoteEnv(value: string): string {
  return /^[\w./:@+-]*$/.test(value) ? value : JSON.stringify(value);
}
