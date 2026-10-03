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

  // PROPOSED_FIXES.md 3.7: the other files credentials conventionally live in.
  it.each([
    ['.env.production', 'API_KEY=dummy-literal-value-123\n', 'dotenv', 'API_KEY'],
    ['.envrc', 'export API_TOKEN=dummy-literal-value-123\n', 'dotenv', 'API_TOKEN'],
    [
      '.npmrc',
      '//registry.npmjs.org/:_authToken=npm_dummyliteralvalue1234567890abcdefgh\n',
      'ini',
      '//registry.npmjs.org/:_authToken',
    ],
    [
      '.pypirc',
      '[pypi]\nusername = __token__\npassword = pypi-dummy-literal-value\n',
      'ini',
      'password',
    ],
    [
      '.netrc',
      'machine api.example.com\n  login me\n  password dummy-literal-value\n',
      'netrc',
      'api.example.com-password',
    ],
    ['credentials.json', '{"client_secret": "dummy-literal-value"}', 'json', 'client_secret'],
    [
      'service-account-prod.json',
      '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEdummy\\n-----END PRIVATE KEY-----\\n"}',
      'json',
      'private_key',
    ],
    [
      'id_ed25519',
      '-----BEGIN OPENSSH PRIVATE KEY-----\ndummy\n-----END OPENSSH PRIVATE KEY-----\n',
      'key',
      '(private key)',
    ],
    [
      'deploy.pem',
      '-----BEGIN RSA PRIVATE KEY-----\ndummy\n-----END RSA PRIVATE KEY-----\n',
      'key',
      '(private key)',
    ],
  ])('finds a literal secret in %s', (filename, content, format, keyPath) => {
    writeFileSync(path.join(dir, filename), content);

    const result = discoverSidecarSecretFiles(dir);

    expect(result.files).toHaveLength(1);
    expect(result.files[0]?.format).toBe(format);
    expect(result.files[0]?.secretFields.map((f) => f.keyPath)).toEqual([keyPath]);
    expect(JSON.stringify(result)).not.toContain('dummy-literal-value');
    expect(JSON.stringify(result)).not.toContain('MIIEdummy');
  });

  it.each(['.env.example', '.env.sample', '.env.template'])(
    'ignores the template %s',
    (filename) => {
      writeFileSync(path.join(dir, filename), 'API_KEY=placeholder-value-123\n');

      expect(discoverSidecarSecretFiles(dir).files).toEqual([]);
    },
  );

  it('ignores a .pem that holds only a certificate', () => {
    writeFileSync(
      path.join(dir, 'server.pem'),
      '-----BEGIN CERTIFICATE-----\nMIIdummy\n-----END CERTIFICATE-----\n',
    );

    expect(discoverSidecarSecretFiles(dir).files).toEqual([]);
  });
});
