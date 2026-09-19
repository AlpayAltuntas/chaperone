import { describe, expect, it } from 'vitest';
import { formatGhaReport } from '../../src/reporters/gha.js';
import type { Finding } from '../../src/model/types.js';
import type { ScanMetadata } from '../../src/reporters/types.js';

const METADATA: ScanMetadata = {
  target: '/fake/target',
  targetRootResolved: true,
  timestamp: '2026-01-01T00:00:00.000Z',
  toolVersion: '0.1.0',
  inspected: [{ path: '/fake/config.yaml', kind: 'config' }],
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

describe('formatGhaReport', () => {
  it('maps severity to a GitHub Actions annotation level (critical/high -> error, medium -> warning, low/info -> notice)', () => {
    const output = formatGhaReport(
      [
        makeFinding({ checkId: 'A', severity: 'critical' }),
        makeFinding({ checkId: 'B', severity: 'high' }),
        makeFinding({ checkId: 'C', severity: 'medium' }),
        makeFinding({ checkId: 'D', severity: 'low' }),
        makeFinding({ checkId: 'E', severity: 'info' }),
      ],
      METADATA,
    );
    const lines = output.split('\n');

    expect(lines[0]).toMatch(/^::error /);
    expect(lines[1]).toMatch(/^::error /);
    expect(lines[2]).toMatch(/^::warning /);
    expect(lines[3]).toMatch(/^::notice /);
    expect(lines[4]).toMatch(/^::notice /);
  });

  it('includes a file= property when a location is known', () => {
    const output = formatGhaReport([makeFinding()], METADATA);

    expect(output).toContain('file=/fake/config.yaml');
  });

  it('omits the file= property when there is no location', () => {
    const output = formatGhaReport(
      [makeFinding({ location: { filePath: null, line: null, detail: null } })],
      METADATA,
    );

    expect(output).not.toContain('file=');
  });

  it('includes a line= property when a line number is known', () => {
    const output = formatGhaReport(
      [makeFinding({ location: { filePath: '/fake/config.yaml', line: 12, detail: null } })],
      METADATA,
    );

    expect(output).toContain('line=12');
  });

  it('escapes a colon and comma in a property value (title)', () => {
    const output = formatGhaReport(
      [makeFinding({ checkId: 'CHAP-SEC-001', title: 'a, title: with punctuation' })],
      METADATA,
    );

    expect(output).toContain('title=CHAP-SEC-001%3A a%2C title%3A with punctuation');
  });

  it('escapes a percent sign and newline in the message data', () => {
    const output = formatGhaReport(
      [makeFinding({ message: '100% broken\nsecond line' })],
      METADATA,
    );

    expect(output).toContain('100%25 broken%0Asecond line');
  });

  it('does not escape a colon/comma in the message data (only in property values)', () => {
    const output = formatGhaReport(
      [makeFinding({ message: 'a: message, with punctuation' })],
      METADATA,
    );

    expect(output).toContain('::a: message, with punctuation');
  });

  it('appends a final ::notice:: summary line with the finding count', () => {
    const output = formatGhaReport([makeFinding(), makeFinding()], METADATA);
    const lastLine = output.split('\n').at(-1);

    expect(lastLine).toBe('::notice::Chaperone scan: 2 findings found.');
  });

  it('handles zero findings, only emitting the summary notice', () => {
    const output = formatGhaReport([], METADATA);

    expect(output).toBe('::notice::Chaperone scan: 0 findings found.');
  });

  it('emits a single error annotation when the target could not be located', () => {
    const output = formatGhaReport([], { ...METADATA, targetRootResolved: false });

    expect(output).toBe('::error::Could not locate an installation to scan.');
  });
});
