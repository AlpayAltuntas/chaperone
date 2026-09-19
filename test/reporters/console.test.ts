import { describe, expect, it } from 'vitest';
import { formatConsoleReport } from '../../src/reporters/console.js';
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

  it('shows a distinct message (not "No findings.") when nothing was even scanned', () => {
    const output = formatConsoleReport([], { ...METADATA, targetRootResolved: false });

    expect(output).toContain('Could not locate an installation to scan.');
    expect(output).not.toContain('No findings.');
  });

  it('lists each skipped path and reason', () => {
    const output = formatConsoleReport([], METADATA);

    expect(output).toContain('Skipped (1):');
    expect(output).toContain('/fake/skills/c/package.json: unparseable manifest: Unexpected token');
  });

  it('omits the Skipped section entirely when nothing was skipped', () => {
    const output = formatConsoleReport([], { ...METADATA, skipped: [] });

    expect(output).not.toContain('Skipped');
  });

  it('shows the posture score and band in the summary line', () => {
    const output = formatConsoleReport(
      [makeFinding({ severity: 'critical' }), makeFinding({ severity: 'low' })],
      METADATA,
    );

    // 100 - 25 (critical) - 3 (low) = 72 -> band C.
    expect(output).toContain('posture score 72/100 (C)');
  });

  it('a clean scan scores 100/A', () => {
    const output = formatConsoleReport([], METADATA);

    expect(output).toContain('posture score 100/100 (A)');
  });

  describe('quiet: true', () => {
    it('prints one compact line per finding instead of the full detail block', () => {
      const output = formatConsoleReport(
        [makeFinding({ checkId: 'CHAP-SEC-001', severity: 'high' })],
        METADATA,
        { quiet: true },
      );

      expect(output).toContain('[CHAP-SEC-001] HIGH');
      expect(output).not.toContain('a secret is exposed');
      expect(output).not.toContain('Remediation:');
    });

    it('still shows the summary/score line', () => {
      const output = formatConsoleReport([makeFinding()], METADATA, { quiet: true });

      expect(output).toMatch(/posture score \d+\/100/);
    });
  });

  describe('summaryOnly: true', () => {
    it('prints no per-finding detail, not even severity group headers', () => {
      const output = formatConsoleReport([makeFinding({ severity: 'critical' })], METADATA, {
        summaryOnly: true,
      });

      expect(output).not.toContain('CRITICAL (');
      expect(output).not.toContain('[CHAP-SEC-001]');
      expect(output).toMatch(/posture score \d+\/100/);
      expect(output).toContain('Summary:');
    });

    it('takes precedence over quiet when both are set', () => {
      const output = formatConsoleReport([makeFinding({ severity: 'critical' })], METADATA, {
        quiet: true,
        summaryOnly: true,
      });

      expect(output).not.toContain('[CHAP-SEC-001]');
    });

    it('suppresses "No findings." too, still shows the summary', () => {
      const output = formatConsoleReport([], METADATA, { summaryOnly: true });

      expect(output).not.toContain('No findings.');
      expect(output).toContain('Summary: 0 findings');
    });
  });
});
