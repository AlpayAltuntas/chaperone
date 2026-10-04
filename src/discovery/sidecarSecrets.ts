import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import type {
  InspectedEntry,
  SecretField,
  SidecarSecretFile,
  SkippedEntry,
} from '../model/types.js';
import { maskConfig, maskSecretValue } from './configParser.js';
import { errorMessage } from './errors.js';
import { detectSecretValue } from './secretValuePatterns.js';

type SidecarFormat = SidecarSecretFile['format'];

// Conventional sidecar-secret filenames, checked directly inside the
// target root alongside the main config (improvement_plan.md 1.6). A
// config referencing `${API_KEY}` is safe on its own — but if a colocated
// `.env`/`secrets.yaml` holds the literal value, that's the single most
// common place a real secret actually lives, and it was previously
// invisible to every CHAP-SEC-* check. Widened in PROPOSED_FIXES.md 3.7
// to the other files credentials conventionally live in.
const SIDECAR_FILES: ReadonlyArray<{ filename: string; format: SidecarFormat }> = [
  { filename: '.env', format: 'dotenv' },
  { filename: '.envrc', format: 'dotenv' },
  { filename: 'secrets.yaml', format: 'yaml' },
  { filename: 'secrets.yml', format: 'yaml' },
  { filename: 'secrets.json', format: 'json' },
  { filename: 'credentials.json', format: 'json' },
  { filename: '.npmrc', format: 'ini' },
  { filename: '.pypirc', format: 'ini' },
  { filename: '.netrc', format: 'netrc' },
  { filename: 'id_rsa', format: 'key' },
  { filename: 'id_ecdsa', format: 'key' },
  { filename: 'id_ed25519', format: 'key' },
];

// `.env.local`, `.env.production`, ... but not the committed templates.
const DOTENV_VARIANT = /^\.env\.(?!example$|sample$|template$|dist$|defaults$)[\w.-]+$/;
const SERVICE_ACCOUNT_JSON = /^service[-_]?account.*\.json$/i;
const KEY_FILE = /\.(?:pem|key)$/i;

/** Which sidecar format a target-root filename is, or null if it isn't one. */
function sidecarFormatFor(filename: string): SidecarFormat | null {
  const known = SIDECAR_FILES.find((f) => f.filename === filename);
  if (known !== undefined) {
    return known.format;
  }
  if (DOTENV_VARIANT.test(filename)) {
    return 'dotenv';
  }
  if (SERVICE_ACCOUNT_JSON.test(filename)) {
    return 'json';
  }
  return KEY_FILE.test(filename) ? 'key' : null;
}

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

  let entries: string[];
  try {
    entries = readdirSync(targetRoot).sort();
  } catch {
    entries = [];
  }

  for (const filename of entries) {
    const format = sidecarFormatFor(filename);
    if (format === null) {
      continue;
    }
    const filePath = path.join(targetRoot, filename);
    try {
      if (!statSync(filePath).isFile()) {
        continue;
      }
      const source = readFileSync(filePath, 'utf8');
      const secretFields = sidecarSecretFields(source, format);
      // A `.pem` that holds only a certificate is not a secret file.
      if (format === 'key' && secretFields.length === 0) {
        continue;
      }
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

function sidecarSecretFields(source: string, format: SidecarFormat): SecretField[] {
  if (format === 'key') {
    // Presence of a private key is the finding; the content is only
    // tested for the PEM header and never stored.
    const match = detectSecretValue(source, maskSecretValue);
    return match?.pattern === 'PEM private key'
      ? [
          {
            keyPath: '(private key)',
            displayValue: '-----BEGIN … PRIVATE KEY-----',
            looksLikeEnvReference: false,
            line: null,
            detectedBy: 'value-pattern',
            pattern: 'PEM private key',
          },
        ]
      : [];
  }
  const rawParsed: unknown =
    format === 'dotenv' || format === 'ini'
      ? parseDotenv(source)
      : format === 'netrc'
        ? parseNetrc(source)
        : format === 'json'
          ? (JSON.parse(source) as unknown)
          : (YAML.parse(source) as unknown);
  return maskConfig(rawParsed).secretFields;
}

// `.netrc`: whitespace-separated `machine <host> login <user> password
// <secret>` tokens, possibly across lines. Only the passwords matter.
function parseNetrc(source: string): Record<string, string> {
  const result: Record<string, string> = {};
  const tokens = source.split(/\s+/).filter((t) => t.length > 0);
  let machine = 'default';
  for (let i = 0; i < tokens.length - 1; i++) {
    const token = tokens[i];
    const next = tokens[i + 1] ?? '';
    if (token === 'machine') {
      machine = next;
    } else if (token === 'password') {
      result[`${machine}-password`] = next;
    }
  }
  return result;
}

// Minimal `.env` parsing: `KEY=value` per line, blank lines and `#`
// comments skipped, surrounding single/double quotes stripped, an
// `export ` prefix dropped. Also reads ini files (`.npmrc`, `.pypirc`):
// `[section]` headers have no `=` and are skipped, and `key = value`
// spacing is trimmed. Known gap vs real dotenv parsers: no multi-line values,
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
    // `.envrc` lines are shell: `export KEY=value`.
    const key = line
      .slice(0, eq)
      .trim()
      .replace(/^export\s+/, '');
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
