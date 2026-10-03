import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSec001PlaintextSecrets } from '../../src/checks/secrets/chapSec001PlaintextSecrets.js';
import { maskConfig, maskSecretValue } from '../../src/discovery/configParser.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { scanExistingLogContent } from '../../src/discovery/logContentScanner.js';
import { detectSecretValue } from '../../src/discovery/secretValuePatterns.js';

// Every value below is a fake, inert example shaped like the real format.
const ALNUM_36 = 'EXAMPLEabcdefghijklmnopqrstuvwxyz1234';

describe('detectSecretValue — positives', () => {
  it.each([
    ['Anthropic API key', `sk-ant-api03-${ALNUM_36}`],
    ['OpenAI API key', `sk-proj-${ALNUM_36}`],
    ['OpenAI-style API key', `sk-${ALNUM_36}`],
    ['Stripe live key', `sk_live_${ALNUM_36}`],
    ['GitHub token', `ghp_${ALNUM_36}`],
    ['GitHub fine-grained token', `github_pat_${ALNUM_36}`],
    ['Slack token', 'xoxb-1234-EXAMPLE-slack'],
    ['AWS access key ID', 'AKIAIOSFODNN7EXAMPLE'],
    ['Google API key', `AIza${ALNUM_36.slice(0, 35)}`],
    ['GitLab token', `glpat-${ALNUM_36}`],
    ['npm token', `npm_${ALNUM_36.slice(0, 36)}`],
    ['Hugging Face token', `hf_${ALNUM_36}`],
    ['Bearer credential', `Bearer sk-proj-${ALNUM_36}`],
    ['Basic credential', 'Basic dXNlcjpwYXNzd29yZA=='],
    [
      'PEM private key',
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEexample\n-----END RSA PRIVATE KEY-----',
    ],
    ['password in URL', 'https://admin:hunter2pass@proxy.example.com/v1'],
  ])('recognizes a %s', (pattern, value) => {
    const match = detectSecretValue(value, maskSecretValue);

    expect(match?.pattern).toBe(pattern);
    expect(match?.masked).not.toContain(value.slice(8, -4));
  });

  it('finds a token embedded in a longer value', () => {
    const match = detectSecretValue(`token ghp_${ALNUM_36} --verbose`, maskSecretValue);

    expect(match?.pattern).toBe('GitHub token');
    expect(match?.masked).toMatch(/^token ghp…1234 --verbose$/);
  });

  it('masks only the password of a URL', () => {
    const match = detectSecretValue(
      'https://admin:hunter2pass@proxy.example.com/v1',
      maskSecretValue,
    );

    expect(match?.masked).toBe('https://admin:***@proxy.example.com/v1');
  });
});

describe('detectSecretValue — near misses', () => {
  it.each([
    ['a short sk- prefix', 'sk-short'],
    ['a word containing a prefix', `task-ant-${ALNUM_36}`],
    ['a prefix embedded in a longer identifier', `xghp_${ALNUM_36}`],
    ['a URL with a user but no password', 'https://admin@proxy.example.com'],
    ['a URL whose password is an env reference', 'https://admin:${PROXY_PASS}@proxy.example.com'],
    ['a bearer env reference', 'Bearer ${API_TOKEN}'],
    ['a short bearer placeholder', 'Bearer x'],
    ['a UUID', '123e4567-e89b-12d3-a456-426614174000'],
    ['a git SHA', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
    ['a plain URL', 'https://api.example.com/v1'],
    ['a public key header', '-----BEGIN PUBLIC KEY-----'],
  ])('ignores %s', (_label, value) => {
    expect(detectSecretValue(value, maskSecretValue)).toBeNull();
  });

  it('never leaves the middle of a matched token in the masked output', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[A-Za-z0-9]{36,60}$/), (body) => {
        const value = `ghp_${body}`;
        const match = detectSecretValue(value, maskSecretValue);
        expect(match).not.toBeNull();
        expect(match?.masked).not.toContain(body.slice(0, -4));
      }),
    );
  });
});

// The probe config from PROPOSED_FIXES.md Appendix A.8: only 1 of 5 was caught.
const PROBE_CONFIG = {
  llm: {
    headers: { Authorization: `Bearer sk-proj-${ALNUM_36}` },
    base_url: 'https://admin:hunter2pass@proxy.example.com/v1',
    aws_access_key_id: 'AKIAIOSFODNN7EXAMPLE',
    github: `ghp_${ALNUM_36}`,
    auth: 'xoxb-1234-EXAMPLE-slack',
  },
};

describe('maskConfig — value-shaped secrets (Appendix A.8)', () => {
  it('catches all five probe secrets', () => {
    const { secretFields } = maskConfig(PROBE_CONFIG);

    expect(secretFields.map((f) => [f.keyPath, f.detectedBy])).toEqual([
      ['llm.headers.Authorization', 'value-pattern'],
      ['llm.base_url', 'value-pattern'],
      ['llm.aws_access_key_id', 'key-name'],
      ['llm.github', 'value-pattern'],
      ['llm.auth', 'key-name'],
    ]);
  });

  it('never keeps a literal value in the masked data', () => {
    const { data } = maskConfig(PROBE_CONFIG);
    const serialized = JSON.stringify(data);

    for (const secret of [ALNUM_36, 'hunter2pass', 'AKIAIOSFODNN7EXAMPLE', '1234-EXAMPLE-slack']) {
      expect(serialized).not.toContain(secret);
    }
  });

  it('catches a token inside an array of arguments', () => {
    const { data, secretFields } = maskConfig({ args: ['--token', `ghp_${ALNUM_36}`] });

    expect(secretFields).toMatchObject([{ keyPath: 'args[1]', pattern: 'GitHub token' }]);
    expect(JSON.stringify(data)).not.toContain(ALNUM_36);
  });

  it.each([
    ['auth', 'none'],
    ['auth_type', 'bearer'],
    ['session_timeout', '30m'],
    ['session', 'redis-store'],
    ['cookie', 'httponly'],
  ])('leaves %s: %s alone', (key, value) => {
    expect(maskConfig({ [key]: value }).secretFields).toEqual([]);
  });

  it.each([
    ['authorization', 'Bearer ${API_TOKEN}'],
    ['api_key', 'Bearer ${API_TOKEN}'],
    ['base_url', 'https://admin:${PROXY_PASS}@proxy.example.com'],
  ])('does not report %s: %s as a literal secret', (key, value) => {
    const literal = maskConfig({ [key]: value }).secretFields.filter(
      (f) => !f.looksLikeEnvReference,
    );
    expect(literal).toEqual([]);
  });
});

describe('value-shaped secrets end to end', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-secretvalues-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('reports every probe secret and keeps none of them in the model', () => {
    writeFileSync(path.join(dir, 'config.json'), JSON.stringify(PROBE_CONFIG));

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSec001PlaintextSecrets.run(model);

    expect(findings).toHaveLength(5);
    const github = findings.find((f) => f.location.detail === 'llm.github');
    expect(github?.message).toContain('looks like a GitHub token');
    const serialized = JSON.stringify(model);
    for (const secret of [ALNUM_36, 'hunter2pass', 'AKIAIOSFODNN7EXAMPLE', '1234-EXAMPLE-slack']) {
      expect(serialized).not.toContain(secret);
    }
  });

  it('finds a logged Authorization header and a bare token in the log', () => {
    const logPath = path.join(dir, 'agent.log');
    writeFileSync(
      logPath,
      [
        `DEBUG outgoing headers: Authorization: Bearer sk-proj-${ALNUM_36}`,
        `INFO cloning with ghp_${ALNUM_36}`,
        `DEBUG api_key=sk-ant-api03-${ALNUM_36}`,
        'INFO proxy https://admin:hunter2pass@proxy.example.com/v1 and https://u:${PASS}@x.example',
        'INFO request_id=8f14e45fceea167a status=ok',
      ].join('\n'),
    );

    const result = scanExistingLogContent(logPath);

    expect(result.matches.map((m) => m.keyName)).toEqual([
      '(Bearer credential)',
      '(GitHub token)',
      'api_key',
      '(password in URL)',
    ]);
    expect(JSON.stringify(result)).not.toContain('hunter2pass');
    expect(JSON.stringify(result)).not.toContain(ALNUM_36);
  });
});
