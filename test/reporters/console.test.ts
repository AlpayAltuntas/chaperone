import { describe, expect, it } from 'vitest';
import { formatConsoleReport } from '../../src/reporters/console.js';
import type { Finding } from '../../src/model/types.js';
import type { ScanMetadata } from '../../src/reporters/types.js';

const METADATA: ScanMetadata = {
  target: '/fake/target',
  targetRootResolved: true,
  timestamp: '2026-01-01T00:00:00.000Z',
  toolVersion: '0.1.0',
  inspectedCount: 5,
  skippedCount: 1,
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

describe('formatConsoleReport', () => {
  it('reports "No findings." and a zeroed summary when there are none', () => {
    const output = formatConsoleReport([], METADATA);

    expect(output).toContain('No findings.');
    expect(output).toContain('Summary: 0 findings (0 critical, 0 high, 0 medium, 0 low, 0 info)');
    expect(output).toContain('Inspected 5 paths, skipped 1.');
  });

  it('groups findings with critical before high', () => {
    const output = formatConsoleReport(
      [
        makeFinding({ checkId: 'HIGH-1', severity: 'high' }),
        makeFinding({ checkId: 'CRIT-1', severity: 'critical' }),
      ],
      METADATA,
    );

    const criticalIndex = output.indexOf('CRITICAL (1)');
    const highIndex = output.indexOf('HIGH (1)');
    expect(criticalIndex).toBeGreaterThanOrEqual(0);
    expect(highIndex).toBeGreaterThan(criticalIndex);
  });

  it('includes check id, message, location, OWASP mapping, and remediation', () => {
    const output = formatConsoleReport([makeFinding()], METADATA);

    expect(output).toContain('[CHAP-SEC-001] Plaintext secrets in config');
    expect(output).toContain('a secret is exposed');
    expect(output).toContain('/fake/config.yaml (llm.api_key)');
    expect(output).toContain('OWASP: LLM06');
    expect(output).toContain('Remediation: use an env var');
  });

  it('counts findings per severity in the summary line', () => {
    const output = formatConsoleReport(
      [
        makeFinding({ severity: 'critical' }),
        makeFinding({ severity: 'critical' }),
        makeFinding({ severity: 'low' }),
      ],
      METADATA,
    );

    expect(output).toContain('Summary: 3 findings (2 critical, 0 high, 0 medium, 1 low, 0 info)');
  });

  it('marks an unresolved target root', () => {
    const output = formatConsoleReport([], { ...METADATA, targetRootResolved: false });

    expect(output).toContain('/fake/target (not found)');
  });
});
