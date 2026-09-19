import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { discoverSidecarSecretFiles } from '../../src/discovery/sidecarSecrets.js';

describe('discoverSidecarSecretFiles', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sidecar-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('finds and masks a literal secret in a .env file', () => {
    writeFileSync(
      path.join(dir, '.env'),
      ['# a comment', '', 'OPENAI_API_KEY=sk-real-looking-dummy-value', 'PLAIN_NAME=hello'].join(
        '\n',
      ),
    );

    const result = discoverSidecarSecretFiles(dir);

    expect(result.files).toHaveLength(1);
    expect(result.files[0]?.format).toBe('dotenv');
    expect(result.files[0]?.secretFields).toHaveLength(1);
    expect(result.files[0]?.secretFields[0]?.keyPath).toBe('OPENAI_API_KEY');
    expect(result.files[0]?.secretFields[0]?.looksLikeEnvReference).toBe(false);
    // The real value must never appear in the discovered model.
    expect(result.files[0]?.secretFields[0]?.displayValue).not.toContain('sk-real-looking-dummy');
  });

  it('strips surrounding quotes from a .env value', () => {
    writeFileSync(path.join(dir, '.env'), 'API_TOKEN="quoted-dummy-value"\n');

    const result = discoverSidecarSecretFiles(dir);

    expect(result.files[0]?.secretFields[0]?.keyPath).toBe('API_TOKEN');
  });

  it('leaves an indirect env-var reference unmasked and unflagged as literal', () => {
    writeFileSync(path.join(dir, 'secrets.yaml'), 'api_key: ${OPENAI_API_KEY}\n');

    const result = discoverSidecarSecretFiles(dir);

    expect(result.files[0]?.secretFields[0]?.looksLikeEnvReference).toBe(true);
  });

  it('parses secrets.json', () => {
    writeFileSync(path.join(dir, 'secrets.json'), JSON.stringify({ api_key: 'dummy-literal' }));

    const result = discoverSidecarSecretFiles(dir);

    expect(result.files).toHaveLength(1);
    expect(result.files[0]?.format).toBe('json');
  });

  it('discovers multiple sidecar files at once', () => {
    writeFileSync(path.join(dir, '.env'), 'API_KEY=one\n');
    writeFileSync(path.join(dir, 'secrets.yaml'), 'api_key: two\n');

    const result = discoverSidecarSecretFiles(dir);

    expect(result.files.map((f) => path.basename(f.path)).sort()).toEqual(['.env', 'secrets.yaml']);
  });

  it('records a skipped entry for an unparseable sidecar file instead of throwing', () => {
    writeFileSync(path.join(dir, 'secrets.json'), '{ not valid json');

    const result = discoverSidecarSecretFiles(dir);

    expect(result.files).toEqual([]);
    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0]?.reason).toContain('unparseable sidecar secret file');
  });

  it('returns nothing when no sidecar file exists', () => {
    const result = discoverSidecarSecretFiles(dir);

    expect(result.files).toEqual([]);
    expect(result.inspected).toEqual([]);
    expect(result.skipped).toEqual([]);
  });
});
