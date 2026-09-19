import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { findingFingerprint, findNewFindings, loadBaseline } from '../../src/config/baseline.js';
import { buildScanReport } from '../../src/reporters/json.js';
import type { Finding } from '../../src/model/types.js';
import type { ScanMetadata } from '../../src/reporters/types.js';

const METADATA: ScanMetadata = {
  target: '/fake/target',
  targetRootResolved: true,
  timestamp: '2026-01-01T00:00:00.000Z',
  toolVersion: '0.1.0',
  inspected: [],
  skipped: [],
};

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

describe('loadBaseline', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-baseline-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('loads a valid saved report', () => {
    const configPath = path.join(dir, 'baseline.json');
    const report = buildScanReport([makeFinding()], METADATA);
    writeFileSync(configPath, JSON.stringify(report));

    const loaded = loadBaseline(configPath);

    expect(loaded.findings).toHaveLength(1);
    expect(loaded.findings[0]?.checkId).toBe('CHAP-SEC-001');
  });

  it('throws when the file does not exist', () => {
    const missing = path.join(dir, 'nope.json');

    expect(() => loadBaseline(missing)).toThrow(/baseline file not found/);
  });

  it('throws when the file is not valid JSON', () => {
    const configPath = path.join(dir, 'bad.json');
    writeFileSync(configPath, '{ not json');

    expect(() => loadBaseline(configPath)).toThrow(/could not parse .* as JSON/);
  });

  it('throws when the file does not match the ScanReport schema', () => {
    const configPath = path.join(dir, 'invalid.json');
    writeFileSync(configPath, JSON.stringify({ not: 'a scan report' }));

    expect(() => loadBaseline(configPath)).toThrow(/invalid baseline file/);
  });
});

describe('findingFingerprint', () => {
  it('is stable across a differing line number', () => {
    const a = makeFinding({ location: { filePath: '/f.yaml', line: 5, detail: 'x' } });
    const b = makeFinding({ location: { filePath: '/f.yaml', line: 42, detail: 'x' } });

    expect(findingFingerprint(a)).toBe(findingFingerprint(b));
  });

  it('differs when the message differs', () => {
    const a = makeFinding({ message: 'first' });
    const b = makeFinding({ message: 'second' });

    expect(findingFingerprint(a)).not.toBe(findingFingerprint(b));
  });

  it('differs when the check ID differs', () => {
    const a = makeFinding({ checkId: 'CHAP-SEC-001' });
    const b = makeFinding({ checkId: 'CHAP-SEC-002' });

    expect(findingFingerprint(a)).not.toBe(findingFingerprint(b));
  });
});

describe('findNewFindings', () => {
  it('excludes findings already present in the baseline', () => {
    const shared = makeFinding({ checkId: 'CHAP-SEC-001' });
    const baseline = buildScanReport([shared], METADATA);
    const current = [shared, makeFinding({ checkId: 'CHAP-NET-001' })];

    const result = findNewFindings(current, baseline);

    expect(result).toHaveLength(1);
    expect(result[0]?.checkId).toBe('CHAP-NET-001');
  });

  it('treats every finding as new when the baseline is empty', () => {
    const baseline = buildScanReport([], METADATA);
    const current = [makeFinding()];

    expect(findNewFindings(current, baseline)).toEqual(current);
  });

  it('returns nothing new when current findings exactly match the baseline', () => {
    const findings = [
      makeFinding({ checkId: 'CHAP-SEC-001' }),
      makeFinding({ checkId: 'CHAP-NET-001' }),
    ];
    const baseline = buildScanReport(findings, METADATA);

    expect(findNewFindings(findings, baseline)).toEqual([]);
  });

  it('is unaffected by a resolved finding present only in the baseline', () => {
    const resolved = makeFinding({ checkId: 'CHAP-SEC-999' });
    const baseline = buildScanReport([resolved], METADATA);

    expect(findNewFindings([], baseline)).toEqual([]);
  });
});
