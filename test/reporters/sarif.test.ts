import { describe, expect, it } from 'vitest';
import { formatSarifReport } from '../../src/reporters/sarif.js';
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

// No JSON-schema validator dependency is pulled in for this (§4: minimal
// dependencies) — these are structural assertions against the SARIF 2.1.0
// shape the spec requires, not a full schema validation.
describe('formatSarifReport', () => {
  it('emits a valid top-level SARIF 2.1.0 log shape', () => {
    const sarif = JSON.parse(formatSarifReport([makeFinding()], METADATA)) as Record<
      string,
      unknown
    >;

    expect(sarif['$schema']).toContain('sarif-schema-2.1.0.json');
    expect(sarif['version']).toBe('2.1.0');
    expect(Array.isArray(sarif['runs'])).toBe(true);
    expect((sarif['runs'] as unknown[]).length).toBe(1);
  });

  it('describes the tool driver with a name, version, and rules array', () => {
    const sarif = JSON.parse(formatSarifReport([makeFinding()], METADATA)) as {
      runs: [{ tool: { driver: { name: string; version: string; rules: unknown[] } } }];
    };
    const driver = sarif.runs[0].tool.driver;

    expect(driver.name).toBe('chaperone');
    expect(driver.version).toBe('0.1.0');
    expect(driver.rules).toHaveLength(1);
  });

  it('deduplicates rules by checkId across repeated findings', () => {
    const sarif = JSON.parse(
      formatSarifReport([makeFinding(), makeFinding({ message: 'another instance' })], METADATA),
    ) as { runs: [{ tool: { driver: { rules: unknown[] } } }] };

    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
  });

  it('maps severity to SARIF level (critical/high -> error, medium -> warning, low/info -> note)', () => {
    const sarif = JSON.parse(
      formatSarifReport(
        [
          makeFinding({ checkId: 'A', severity: 'critical' }),
          makeFinding({ checkId: 'B', severity: 'high' }),
          makeFinding({ checkId: 'C', severity: 'medium' }),
          makeFinding({ checkId: 'D', severity: 'low' }),
          makeFinding({ checkId: 'E', severity: 'info' }),
        ],
        METADATA,
      ),
    ) as { runs: [{ results: Array<{ ruleId: string; level: string }> }] };
    const levelByRule = Object.fromEntries(sarif.runs[0].results.map((r) => [r.ruleId, r.level]));

    expect(levelByRule).toEqual({ A: 'error', B: 'error', C: 'warning', D: 'note', E: 'note' });
  });

  it('includes a physicalLocation with a file:// artifact URI when a location is known', () => {
    const sarif = JSON.parse(formatSarifReport([makeFinding()], METADATA)) as {
      runs: [
        { results: [{ locations: [{ physicalLocation: { artifactLocation: { uri: string } } }] }] },
      ];
    };
    const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;

    expect(uri).toMatch(/^file:\/\//);
    expect(uri).toContain('config.yaml');
  });

  it('omits locations when the finding has no file path', () => {
    const sarif = JSON.parse(
      formatSarifReport(
        [makeFinding({ location: { filePath: null, line: null, detail: null } })],
        METADATA,
      ),
    ) as { runs: [{ results: [Record<string, unknown>] }] };

    expect(sarif.runs[0].results[0]['locations']).toBeUndefined();
  });

  it('produces valid JSON text with an empty results array for zero findings', () => {
    const sarif = JSON.parse(formatSarifReport([], METADATA)) as { runs: [{ results: unknown[] }] };

    expect(sarif.runs[0].results).toEqual([]);
  });
});
