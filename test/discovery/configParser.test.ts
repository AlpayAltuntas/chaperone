import { describe, expect, it } from 'vitest';
import {
  looksLikeEnvReference,
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

  it.each(['sk-ant-abc123', 'plainpassword', 'env-FOO', '${FOO'])(
    'does not treat %s as an env reference',
    (value) => {
      expect(looksLikeEnvReference(value)).toBe(false);
    },
  );
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
      { keyPath: 'llm.api_key', displayValue: 'sk-…mnop', looksLikeEnvReference: false },
    ]);
    expect(JSON.stringify(data)).not.toContain('abcdefghijklmnop');
  });

  it('leaves env-reference values visible and marks them as such', () => {
    const { data, secretFields } = maskConfig({ llm: { api_key: '${ANTHROPIC_API_KEY}' } });

    expect(secretFields).toEqual([
      { keyPath: 'llm.api_key', displayValue: '${ANTHROPIC_API_KEY}', looksLikeEnvReference: true },
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
});
