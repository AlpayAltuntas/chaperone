import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  applyChaperoneConfig,
  DEFAULT_CONFIG_FILENAME,
  loadChaperoneConfig,
} from '../../src/config/chaperoneConfig.js';
import type { Finding } from '../../src/model/types.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    checkId: 'CHAP-SEC-001',
    title: 'Plaintext secrets in config',
    severity: 'high',
    category: 'secrets',
    owasp: 'LLM06',
    message: 'a secret is exposed',
    location: { filePath: '/fake/config.yaml', line: null, detail: 'llm.api_key' },
    remediation: 'use an env var',
    ...overrides,
  };
}

const KNOWN_IDS = new Set(['CHAP-SEC-001', 'CHAP-NET-001', 'CHAP-SUP-003']);

describe('loadChaperoneConfig', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-config-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('returns an empty config and null path when no explicit path is given and no default file exists', () => {
    const explicitlyEmptyDir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-config-empty-'));
    const originalCwd = process.cwd();
    process.chdir(explicitlyEmptyDir);
    try {
      const result = loadChaperoneConfig();
      expect(result).toEqual({ config: {}, path: null });
    } finally {
      process.chdir(originalCwd);
      rmSync(explicitlyEmptyDir, { recursive: true, force: true });
    }
  });

  it('auto-discovers the default filename in the current directory', () => {
    const configPath = path.join(dir, DEFAULT_CONFIG_FILENAME);
    writeFileSync(configPath, JSON.stringify({ disabledChecks: ['CHAP-SEC-001'] }));

    const originalCwd = process.cwd();
    process.chdir(dir);
    try {
      const result = loadChaperoneConfig();
      expect(result.path).toBe(DEFAULT_CONFIG_FILENAME);
      expect(result.config).toEqual({ disabledChecks: ['CHAP-SEC-001'] });
    } finally {
      process.chdir(originalCwd);
    }
  });

  it('loads and validates an explicit path', () => {
    const configPath = path.join(dir, 'custom.json');
    writeFileSync(configPath, JSON.stringify({ severityOverrides: { 'CHAP-SEC-001': 'low' } }));

    const result = loadChaperoneConfig(configPath);

    expect(result.path).toBe(configPath);
    expect(result.config).toEqual({ severityOverrides: { 'CHAP-SEC-001': 'low' } });
  });

  it('throws when an explicit path does not exist', () => {
    const missing = path.join(dir, 'nope.json');

    expect(() => loadChaperoneConfig(missing)).toThrow(/config file not found/);
  });

  it('throws when the file is not valid JSON', () => {
    const configPath = path.join(dir, 'bad.json');
    writeFileSync(configPath, '{ not json');

    expect(() => loadChaperoneConfig(configPath)).toThrow(/could not parse .* as JSON/);
  });

  it('throws when the file does not match the schema', () => {
    const configPath = path.join(dir, 'invalid.json');
    writeFileSync(configPath, JSON.stringify({ severityOverrides: { 'CHAP-SEC-001': 'extreme' } }));

    expect(() => loadChaperoneConfig(configPath)).toThrow(/invalid .*severityOverrides/);
  });
});

describe('applyChaperoneConfig', () => {
  it('returns findings unchanged and no warnings for an empty config', () => {
    const findings = [makeFinding()];

    const result = applyChaperoneConfig(findings, {}, KNOWN_IDS);

    expect(result.findings).toEqual(findings);
    expect(result.warnings).toEqual([]);
  });

  it('applies a severity override to matching findings', () => {
    const findings = [makeFinding({ checkId: 'CHAP-SEC-001', severity: 'high' })];

    const result = applyChaperoneConfig(
      findings,
      { severityOverrides: { 'CHAP-SEC-001': 'low' } },
      KNOWN_IDS,
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe('low');
    expect(result.warnings).toEqual([]);
  });

  it('does not affect findings for other check IDs', () => {
    const findings = [makeFinding({ checkId: 'CHAP-NET-001', severity: 'critical' })];

    const result = applyChaperoneConfig(
      findings,
      { severityOverrides: { 'CHAP-SEC-001': 'low' } },
      KNOWN_IDS,
    );

    expect(result.findings[0]?.severity).toBe('critical');
  });

  it('removes findings suppressed by an active ignore entry', () => {
    const findings = [
      makeFinding({ checkId: 'CHAP-SEC-001' }),
      makeFinding({ checkId: 'CHAP-NET-001' }),
    ];

    const result = applyChaperoneConfig(
      findings,
      { ignore: [{ checkId: 'CHAP-SEC-001', reason: 'accepted risk' }] },
      KNOWN_IDS,
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.checkId).toBe('CHAP-NET-001');
    expect(result.warnings).toEqual([]);
  });

  it('does not suppress an expired ignore entry, and warns instead', () => {
    const findings = [makeFinding({ checkId: 'CHAP-SEC-001' })];
    const now = new Date('2026-06-01T00:00:00.000Z');

    const result = applyChaperoneConfig(
      findings,
      {
        ignore: [{ checkId: 'CHAP-SEC-001', reason: 'temp fix pending', expires: '2026-01-01' }],
      },
      KNOWN_IDS,
      now,
    );

    expect(result.findings).toHaveLength(1);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toMatch(/expired on 2026-01-01/);
    expect(result.warnings[0]).toContain('temp fix pending');
  });

  it('still suppresses an ignore entry whose expiry date is in the future', () => {
    const findings = [makeFinding({ checkId: 'CHAP-SEC-001' })];
    const now = new Date('2026-01-01T00:00:00.000Z');

    const result = applyChaperoneConfig(
      findings,
      { ignore: [{ checkId: 'CHAP-SEC-001', expires: '2026-06-01' }] },
      KNOWN_IDS,
      now,
    );

    expect(result.findings).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  it('warns about a severityOverrides entry referencing an unknown check ID', () => {
    const result = applyChaperoneConfig(
      [],
      { severityOverrides: { 'CHAP-FAKE-999': 'low' } },
      KNOWN_IDS,
    );

    expect(result.warnings).toEqual([
      ".chaperonerc.json: severityOverrides references unknown check ID 'CHAP-FAKE-999'",
    ]);
  });

  it('warns about an ignore entry referencing an unknown check ID', () => {
    const result = applyChaperoneConfig([], { ignore: [{ checkId: 'CHAP-FAKE-999' }] }, KNOWN_IDS);

    expect(result.warnings).toEqual([
      ".chaperonerc.json: ignore entry references unknown check ID 'CHAP-FAKE-999'",
    ]);
  });

  it('is unaffected by disabledChecks — that field is handled upstream, not by this function', () => {
    const findings = [makeFinding({ checkId: 'CHAP-SEC-001' })];

    const result = applyChaperoneConfig(findings, { disabledChecks: ['CHAP-SEC-001'] }, KNOWN_IDS);

    expect(result.findings).toEqual(findings);
  });
});
