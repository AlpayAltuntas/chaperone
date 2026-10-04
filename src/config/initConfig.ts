import { existsSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { DEFAULT_CONFIG_FILENAME } from './chaperoneConfig.js';

// `chaperone init` (PROPOSED_FIXES.md 7.4.1): a starter .chaperonerc.json.
// JSON has no comments, so explanations go in "//" keys, which the config
// schema ignores.
export const STARTER_CONFIG = {
  '//': 'Chaperone scan settings. Every key is optional. See README: "Suppressions & overrides".',
  '//severityOverrides':
    'Change a check\'s severity for this repo, e.g. { "CHAP-AGY-004": "low" }.',
  severityOverrides: {},
  '//ignore':
    'Suppress a check, with a reason and an expiry date after which it reports again, e.g. { "checkId": "CHAP-SUP-002", "reason": "vendored skill, tracked in JIRA-123", "expires": "2027-01-31" }.',
  ignore: [],
  '//disabledChecks': 'Check IDs to skip entirely, e.g. ["CHAP-SEC-007"].',
  disabledChecks: [],
  '//plugins':
    'Paths to plugin modules. A plugin runs with full access and no sandbox: only list code you have read and trust.',
  plugins: [],
};

/** Writes the starter config into `dir`; refuses to overwrite an existing file. Returns the path written. */
export function writeStarterConfig(dir: string): string {
  const file = path.join(dir, DEFAULT_CONFIG_FILENAME);
  if (existsSync(file)) {
    throw new Error(`${file} already exists; not overwriting it`);
  }
  writeFileSync(file, `${JSON.stringify(STARTER_CONFIG, null, 2)}\n`, { flag: 'wx' });
  return file;
}
