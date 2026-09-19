import { describe, expect, it } from 'vitest';
import { formatMarkdownReport } from '../../src/reporters/markdown.js';
import type { Finding } from '../../src/model/types.js';
import type { ScanMetadata } from '../../src/reporters/types.js';

const METADATA: ScanMetadata = {
  target: '/fake/target',
  targetRootResolved: true,
  timestamp: '2026-01-01T00:00:00.000Z',
  toolVersion: '0.1.0',
  inspected: [{ path: '/fake/config.yaml', kind: 'config' }],
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

describe('formatMarkdownReport', () => {
  it('renders a header with target and timestamp', () => {
    const output = formatMarkdownReport([], METADATA);

    expect(output).toContain('# Chaperone scan report');
    expect(output).toContain('**Target:** `/fake/target`');
    expect(output).toContain('chaperone v0.1.0');
  });

  it('renders a Markdown table with one row per finding', () => {
    const output = formatMarkdownReport(
      [makeFinding({ checkId: 'A' }), makeFinding({ checkId: 'B' })],
      METADATA,
    );

    expect(output).toContain('| Severity | Check | Message | Location |');
    expect(output).toContain('| --- | --- | --- | --- |');
    expect(output).toContain('`A`');
    expect(output).toContain('`B`');
  });

  it('sorts findings most severe first', () => {
    const output = formatMarkdownReport(
      [
        makeFinding({ checkId: 'LOW-1', severity: 'low' }),
        makeFinding({ checkId: 'CRIT-1', severity: 'critical' }),
      ],
      METADATA,
    );

    expect(output.indexOf('CRIT-1')).toBeLessThan(output.indexOf('LOW-1'));
  });

  it('escapes a pipe character in a message so it cannot break the table', () => {
    const output = formatMarkdownReport(
      [makeFinding({ message: 'value contains a | pipe character' })],
      METADATA,
    );

    expect(output).toContain('value contains a \\| pipe character');
  });

  it('collapses a newline in a message to a space', () => {
    const output = formatMarkdownReport([makeFinding({ message: 'line one\nline two' })], METADATA);

    expect(output).toContain('line one line two');
    expect(output).not.toContain('line one\nline two');
  });

  it('shows "No findings." when there are none but the target resolved', () => {
    const output = formatMarkdownReport([], METADATA);

    expect(output).toContain('No findings.');
  });

  it('shows a distinct message when the target could not be located', () => {
    const output = formatMarkdownReport([], { ...METADATA, targetRootResolved: false });

    expect(output).toContain('Could not locate an installation to scan.');
    expect(output).not.toContain('No findings.');
  });

  it('lists the skipped section', () => {
    const output = formatMarkdownReport([], METADATA);

    expect(output).toContain('**Skipped (1):**');
    expect(output).toContain('`/fake/skills/c/package.json`: unparseable manifest');
  });

  it('includes the posture score and band in the summary line', () => {
    const output = formatMarkdownReport([makeFinding({ severity: 'critical' })], METADATA);

    // 100 - 25 (critical) = 75 -> band B.
    expect(output).toContain('posture score 75/100 (B)');
  });

  it('renders a dash for a finding with no location', () => {
    const output = formatMarkdownReport(
      [makeFinding({ location: { filePath: null, line: null, detail: null } })],
      METADATA,
    );

    expect(output).toContain('| — |');
  });
});
