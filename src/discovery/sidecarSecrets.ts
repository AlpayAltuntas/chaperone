import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import type { InspectedEntry, SidecarSecretFile, SkippedEntry } from '../model/types.js';
import { maskConfig } from './configParser.js';
import { errorMessage } from './errors.js';

// Conventional sidecar-secret filenames, checked directly inside the
// target root alongside the main config (improvement_plan.md 1.6). A
// config referencing `${API_KEY}` is safe on its own — but if a colocated
// `.env`/`secrets.yaml` holds the literal value, that's the single most
// common place a real secret actually lives, and it was previously
// invisible to every CHAP-SEC-* check.
const SIDECAR_FILES: ReadonlyArray<{ filename: string; format: 'dotenv' | 'yaml' | 'json' }> = [
  { filename: '.env', format: 'dotenv' },
  { filename: '.env.local', format: 'dotenv' },
  { filename: 'secrets.yaml', format: 'yaml' },
  { filename: 'secrets.yml', format: 'yaml' },
  { filename: 'secrets.json', format: 'json' },
];

export interface SidecarSecretDiscoveryResult {
  files: SidecarSecretFile[];
  inspected: InspectedEntry[];
  skipped: SkippedEntry[];
}

/**
 * Looks for conventional sidecar secret files alongside the main config
 * and feeds each one through the exact same masking pipeline
 * configParser.ts already applies to config.yaml — no literal secret
 * value is ever retained here either.
 */
export function discoverSidecarSecretFiles(targetRoot: string): SidecarSecretDiscoveryResult {
  const files: SidecarSecretFile[] = [];
  const inspected: InspectedEntry[] = [];
  const skipped: SkippedEntry[] = [];

  for (const { filename, format } of SIDECAR_FILES) {
    const filePath = path.join(targetRoot, filename);
    if (!existsSync(filePath)) {
      continue;
    }
    try {
      const source = readFileSync(filePath, 'utf8');
      const rawParsed: unknown =
        format === 'dotenv'
          ? parseDotenv(source)
          : format === 'json'
            ? (JSON.parse(source) as unknown)
            : (YAML.parse(source) as unknown);
      const { secretFields } = maskConfig(rawParsed);
      files.push({ path: filePath, format, secretFields });
      inspected.push({ path: filePath, kind: 'config' });
    } catch (err) {
      skipped.push({
        path: filePath,
        reason: `unparseable sidecar secret file: ${errorMessage(err)}`,
      });
    }
  }

  return { files, inspected, skipped };
}

// Minimal `.env` parsing: `KEY=value` per line, blank lines and `#`
// comments skipped, surrounding single/double quotes stripped. Known gap
// vs real dotenv parsers: no multi-line values, no `export KEY=` prefix,
// no `\n`-escape unescaping — deliberately small, matching
// gitignoreMatch.ts's precedent of a documented partial implementation
// rather than a full spec.
function parseDotenv(source: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const rawLine of source.split('\n')) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    const eq = line.indexOf('=');
    if (eq === -1) {
      continue;
    }
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (key.length > 0) {
      result[key] = value;
    }
  }
  return result;
}
