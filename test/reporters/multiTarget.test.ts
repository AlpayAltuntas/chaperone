import { describe, expect, it } from 'vitest';
import { renderMultiTargetReport, type TargetReport } from '../../src/reporters/index.js';
import type { Finding } from '../../src/model/types.js';
import type { ScanMetadata } from '../../src/reporters/types.js';

function makeMetadata(target: string): ScanMetadata {
  return {
    target,
    targetRootResolved: true,
    timestamp: '2026-01-01T00:00:00.000Z',
    toolVersion: '0.1.0',
    inspected: [],
    skipped: [],
  };
}

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

describe('renderMultiTargetReport — a single target', () => {
  it("is byte-for-byte identical to renderReport's own output, for every format", async () => {
    const { renderReport, REPORT_FORMATS } = await import('../../src/reporters/index.js');
    const findings = [makeFinding()];
    const metadata = makeMetadata('/fake/one');
    const target: TargetReport = { findings, metadata };

    for (const format of REPORT_FORMATS) {
      expect(renderMultiTargetReport(format, [target])).toBe(
        renderReport(format, findings, metadata),
      );
    }
  });
});

describe('renderMultiTargetReport — multiple targets', () => {
  const targets: TargetReport[] = [
    { findings: [makeFinding({ checkId: 'CHAP-SEC-001' })], metadata: makeMetadata('/fake/one') },
    { findings: [makeFinding({ checkId: 'CHAP-NET-001' })], metadata: makeMetadata('/fake/two') },
  ];

  it('aggregates json as an array of schema-valid report objects', () => {
    const output = renderMultiTargetReport('json', targets);
    const parsed = JSON.parse(output) as Array<{ target: string; findings: unknown[] }>;

    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(2);
    expect(parsed[0]?.target).toBe('/fake/one');
    expect(parsed[1]?.target).toBe('/fake/two');
  });

  it('merges sarif into one multi-run document', () => {
    const output = renderMultiTargetReport('sarif', targets);
    const parsed = JSON.parse(output) as { version: string; runs: unknown[] };

    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toHaveLength(2);
  });

  it('header-separates console/markdown/html/gha output, one section per target', () => {
    for (const format of ['console', 'markdown', 'html', 'gha'] as const) {
      const output = renderMultiTargetReport(format, targets);
      expect(output).toContain('===== Target 1/2: /fake/one =====');
      expect(output).toContain('===== Target 2/2: /fake/two =====');
    }
  });

  it('handles zero targets without throwing — an empty JSON array, an empty string for header-concatenated formats', () => {
    expect(renderMultiTargetReport('json', [])).toBe('[]');
    expect(renderMultiTargetReport('console', [])).toBe('');
  });
});
