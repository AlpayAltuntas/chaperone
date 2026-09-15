import { describe, expect, it } from 'vitest';
import { buildScanReport, formatJsonReport } from '../../src/reporters/json.js';
import { ScanReportSchema } from '../../src/reporters/schema.js';
import type { Finding } from '../../src/model/types.js';
import type { ScanMetadata } from '../../src/reporters/types.js';

const METADATA: ScanMetadata = {
  target: '/fake/target',
  targetRootResolved: true,
  timestamp: '2026-01-01T00:00:00.000Z',
  toolVersion: '0.1.0',
  inspected: [
    { path: '/fake/config.yaml', kind: 'config' },
    { path: '/fake/skills/a/index.js', kind: 'skill-source' },
    { path: '/fake/skills/a/package.json', kind: 'skill-manifest' },
    { path: '/fake/skills/b/index.js', kind: 'skill-source' },
    { path: '/fake/.gitignore', kind: 'gitignore' },
  ],
  skipped: [
    { path: '/fake/skills/c/package.json', reason: 'unparseable manifest: Unexpected token' },
  ],
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

describe('buildScanReport / formatJsonReport', () => {
  it('produces a report that validates against ScanReportSchema', () => {
    const report = buildScanReport([makeFinding()], METADATA);

    expect(() => ScanReportSchema.parse(report)).not.toThrow();
  });

  it('includes tool/target/timestamp metadata verbatim', () => {
    const report = buildScanReport([], METADATA);

    expect(report.tool).toEqual({ name: 'chaperone', version: '0.1.0' });
    expect(report.target).toBe('/fake/target');
    expect(report.timestamp).toBe('2026-01-01T00:00:00.000Z');
    expect(report.inspected).toHaveLength(5);
    expect(report.skipped).toEqual([
      { path: '/fake/skills/c/package.json', reason: 'unparseable manifest: Unexpected token' },
    ]);
  });

  it('computes a full bySeverity breakdown, including zero counts', () => {
    const report = buildScanReport(
      [makeFinding({ severity: 'critical' }), makeFinding({ severity: 'critical' })],
      METADATA,
    );

    expect(report.summary.bySeverity).toEqual({ critical: 2, high: 0, medium: 0, low: 0, info: 0 });
    expect(report.summary.totalFindings).toBe(2);
  });

  it('includes the posture score and band', () => {
    const report = buildScanReport([makeFinding({ severity: 'critical' })], METADATA);

    expect(report.summary.score).toBe(75);
    expect(report.summary.band).toBe('B');
  });

  it('formatJsonReport emits valid, schema-conformant JSON text', () => {
    const text = formatJsonReport([makeFinding()], METADATA);
    const parsed: unknown = JSON.parse(text);

    expect(() => ScanReportSchema.parse(parsed)).not.toThrow();
  });

  it('carries findings through with secrets already masked upstream (never re-exposes raw values)', () => {
    const text = formatJsonReport(
      [makeFinding({ message: 'literal value sk-…wxyz masked upstream' })],
      METADATA,
    );

    expect(text).toContain('sk-…wxyz');
    expect(text).not.toMatch(/sk-[a-zA-Z0-9]{20,}/); // no unmasked-looking literal key survives
  });
});
