import { describe, expect, it } from 'vitest';
import {
  createLineLookup,
  extractEnvVarName,
  looksLikeEnvReference,
  looksLikeSecretKeyName,
  maskConfig,
  maskSecretValue,
  parseConfigSource,
} from '../../src/discovery/configParser.js';

describe('parseConfigSource', () => {
  it('parses YAML', () => {
    expect(parseConfigSource('a:\n  b: 1\n', 'yaml')).toEqual({ a: { b: 1 } });
  });

  it('parses JSON', () => {
    expect(parseConfigSource('{"a":{"b":1}}', 'json')).toEqual({ a: { b: 1 } });
  });

  it('throws on malformed input rather than silently returning garbage', () => {
    expect(() => parseConfigSource('{not valid json', 'json')).toThrow();
    expect(() => parseConfigSource('a:\n  - b\n  c: [', 'yaml')).toThrow();
  });
});

describe('looksLikeEnvReference', () => {
  it.each(['${FOO}', '$FOO', 'env:FOO', 'ENV:FOO_BAR'])(
    'recognizes %s as an env reference',
    (value) => {
      expect(looksLikeEnvReference(value)).toBe(true);
    },
  );

  // Regression test for improvement_plan.md 1.5: bash/docker-compose-style
  // parameter expansion with a default/error fallback was previously
  // treated as a literal secret (false positive).
  it.each(['${FOO:-default}', '${FOO:=default}', '${FOO:?missing value}', '${FOO:+alt}'])(
    'recognizes %s (default/error/alt fallback syntax) as an env reference',
    (value) => {
      expect(looksLikeEnvReference(value)).toBe(true);
    },
  );

  it.each(['sk-ant-abc123', 'plainpassword', 'env-FOO', '${FOO'])(
    'does not treat %s as an env reference',
    (value) => {
      expect(looksLikeEnvReference(value)).toBe(false);
    },
  );
});

describe('extractEnvVarName', () => {
  it.each([
    ['${FOO}', 'FOO'],
    ['$FOO', 'FOO'],
    ['env:FOO', 'FOO'],
    ['ENV:FOO_BAR', 'FOO_BAR'],
  ] as const)('extracts the variable name from %s', (value, expected) => {
    expect(extractEnvVarName(value)).toBe(expected);
  });

  // CHAP-SEC-007 deliberately can't say anything useful once a fallback
  // is present (the reference resolves to something even when the
  // variable itself is unset) — extraction returns null so the check
  // skips these rather than risk a false positive.
  it.each(['${FOO:-default}', '${FOO:=default}', '${FOO:?missing value}', '${FOO:+alt}'])(
    'returns null for %s (has a fallback/default)',
    (value) => {
      expect(extractEnvVarName(value)).toBeNull();
    },
  );

  it('returns null for a non-reference value', () => {
    expect(extractEnvVarName('plainpassword')).toBeNull();
  });
});

// Regression tests for improvement_plan.md 1.2: the old substring regex
// only recognized the literal sequence "api_key" for the "key" family —
// a bare `key` segment (private_key, ssh_key, encryption_key, ...) wasn't
// matched at all — while simultaneously false-positiving on any word that
// merely *contained* "token"/"secret"/etc. as a substring (tokenizer,
// secretary-style names). Segment-based whole-word matching fixes both.
describe('looksLikeSecretKeyName', () => {
  it.each([
    'api_key',
    'apiKey',
    'API_KEY',
    'apikey',
    'api-key',
    'private_key',
    'privateKey',
    'ssh_key',
    'encryption_key',
    'signing_key',
    'master_key',
    'key',
    'token',
    'auth_token',
    'authToken',
    'secret',
    'client_secret',
    'password',
    'db_password',
    'credential',
    'credentials',
  ])('recognizes %s as a secret-shaped key name', (key) => {
    expect(looksLikeSecretKeyName(key)).toBe(true);
  });

  it.each([
    'tokenizer_model',
    'tokenizer',
    'keyboard_layout',
    'keyword',
    'monkey',
    'turkey',
    'secretary',
    'provider',
    'model',
    'enabled',
  ])('does not treat %s as a secret-shaped key name', (key) => {
    expect(looksLikeSecretKeyName(key)).toBe(false);
  });
});

describe('maskSecretValue', () => {
  it('keeps a short prefix/suffix for long values', () => {
    expect(maskSecretValue('sk-ant-api03-abcdefghijklmnop')).toBe('sk-…mnop');
  });

  it('fully masks short values', () => {
    expect(maskSecretValue('abcd')).toBe('****');
  });
});

describe('maskConfig', () => {
  it('masks literal secret-like fields and records their location', () => {
    const { data, secretFields } = maskConfig({ llm: { api_key: 'sk-ant-abcdefghijklmnop' } });

    expect(secretFields).toEqual([
      {
        keyPath: 'llm.api_key',
        displayValue: 'sk-…mnop',
        looksLikeEnvReference: false,
        line: null,
      },
    ]);
    expect(JSON.stringify(data)).not.toContain('abcdefghijklmnop');
  });

  it('leaves env-reference values visible and marks them as such', () => {
    const { data, secretFields } = maskConfig({ llm: { api_key: '${ANTHROPIC_API_KEY}' } });

    expect(secretFields).toEqual([
      {
        keyPath: 'llm.api_key',
        displayValue: '${ANTHROPIC_API_KEY}',
        looksLikeEnvReference: true,
        line: null,
      },
    ]);
    expect(data).toEqual({ llm: { api_key: '${ANTHROPIC_API_KEY}' } });
  });

  it('does not touch non-secret-shaped fields', () => {
    const { data, secretFields } = maskConfig({ gateway: { host: '127.0.0.1', port: 18789 } });

    expect(secretFields).toEqual([]);
    expect(data).toEqual({ gateway: { host: '127.0.0.1', port: 18789 } });
  });

  it('masks secret-like fields nested inside arrays', () => {
    const { secretFields } = maskConfig({ channels: [{ token: 'literal-value-here' }] });

    expect(secretFields).toHaveLength(1);
    expect(secretFields[0]?.keyPath).toBe('channels[0].token');
  });

  it('returns null data for non-object, non-array input', () => {
    expect(maskConfig('just a string').data).toBeNull();
    expect(maskConfig(null).data).toBeNull();
    expect(maskConfig(42).data).toBeNull();
  });

  it('masks a private_key field end-to-end (regression for 1.2 — previously invisible)', () => {
    const { data, secretFields } = maskConfig({
      tls: { private_key: 'abcdefghijklmnopqrstuvwxyz' },
    });

    expect(secretFields).toHaveLength(1);
    expect(secretFields[0]?.keyPath).toBe('tls.private_key');
    expect(JSON.stringify(data)).not.toContain('abcdefghijklmnopqrstuvwxyz');
  });

  it('does not mask a field that merely contains "token" as a substring (regression for 1.2)', () => {
    const { data, secretFields } = maskConfig({ llm: { tokenizer_model: 'cl100k_base' } });

    expect(secretFields).toEqual([]);
    expect(data).toEqual({ llm: { tokenizer_model: 'cl100k_base' } });
  });
});

// improvement_plan.md 1.17.
describe('createLineLookup', () => {
  const YAML_SOURCE = [
    'llm:',
    '  provider: anthropic',
    '  api_key: sk-ant-test-value',
    'channels:',
    '  telegram:',
    '    bot_token: abc123',
    'trust:',
    '  tool_allowlist:',
    '    - notes.writeNote',
    '    - weather.fetchForecast',
    '',
  ].join('\n');

  it('resolves a top-level key path to its 1-indexed source line', () => {
    const lookup = createLineLookup(YAML_SOURCE, 'yaml');

    expect(lookup('llm.api_key')).toBe(3);
  });

  it('resolves a nested key path', () => {
    const lookup = createLineLookup(YAML_SOURCE, 'yaml');

    expect(lookup('channels.telegram.bot_token')).toBe(6);
  });

  it('resolves an array-index key path', () => {
    const lookup = createLineLookup(YAML_SOURCE, 'yaml');

    expect(lookup('trust.tool_allowlist[1]')).toBe(10);
  });

  it('returns null for a key path that does not exist in the document', () => {
    const lookup = createLineLookup(YAML_SOURCE, 'yaml');

    expect(lookup('llm.does_not_exist')).toBeNull();
  });

  it('always returns null for JSON — no CST-with-positions available (documented limitation)', () => {
    const lookup = createLineLookup('{"llm": {"api_key": "sk-ant-test"}}', 'json');

    expect(lookup('llm.api_key')).toBeNull();
  });

  it('returns a no-op lookup (never throws) for unparseable YAML', () => {
    const lookup = createLineLookup('a:\n  - b\n  c: [', 'yaml');

    expect(lookup('a.c')).toBeNull();
  });
});
