import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import AjvDraft04 from 'ajv-draft-04';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { runChecks } from '../../src/engine/index.js';
import { formatSarifReport } from '../../src/reporters/sarif.js';
import { renderMultiTargetReport } from '../../src/reporters/index.js';
import type { ScanMetadata } from '../../src/reporters/types.js';

// PROPOSED_FIXES.md 4.1: validate real output against the official SARIF
// 2.1.0 schema, vendored under test/fixtures so the test needs no network.
// The schema is JSON Schema draft-04, which ajv 8 only supports through
// the ajv-draft-04 build.
const schema = JSON.parse(
  readFileSync(path.join('test', 'fixtures', 'sarif-schema-2.1.0.json'), 'utf8'),
) as object;
// A CommonJS module: under NodeNext the default import is the module, and
// the class is its `default` (the same object at runtime).
const ajv = new AjvDraft04.default({ allErrors: true, strict: false });
const validate = ajv.compile(schema);

interface SarifShape {
  runs: Array<{
    tool: { driver: { rules: Array<{ id: string; properties: Record<string, unknown> }> } };
    invocations: Array<{ executionSuccessful: boolean }>;
    results: Array<{
      partialFingerprints: Record<string, string>;
      locations?: Array<{
        physicalLocation: { artifactLocation: { uri: string; uriBaseId?: string } };
      }>;
      relatedLocations?: unknown[];
    }>;
  }>;
}

describe('SARIF output — schema and code-scanning shape', () => {
  let dir: string;
  let sarif: string;

  beforeAll(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sarif-schema-'));
    cpSync(path.join('test', 'fixtures', 'vulnerable-agent'), dir, { recursive: true });
    mkdirSync(path.join(dir, '.git'));
    chmodSync(path.join(dir, 'config.yaml'), 0o644);
    const { model, targetRootResolved } = discoverAgent({ targetPath: dir });
    const { findings } = runChecks(model, ALL_CHECKS);
    const metadata: ScanMetadata = {
      target: model.targetRoot,
      targetRootResolved,
      timestamp: '2026-01-01T00:00:00.000Z',
      toolVersion: '0.0.0',
      inspected: model.inspected,
      skipped: model.skipped,
      checks: ALL_CHECKS,
      sourceRoot: model.git.gitRootPath ?? model.targetRoot,
    };
    sarif = formatSarifReport(findings, metadata);
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('validates against the SARIF 2.1.0 schema', () => {
    const valid = validate(JSON.parse(sarif));
    expect(validate.errors ?? []).toEqual([]);
    expect(valid).toBe(true);
  });

  it('validates a multi-target (--all) document too', () => {
    const doc = JSON.parse(
      renderMultiTargetReport('sarif', [
        {
          findings: [],
          metadata: {
            target: '/a',
            targetRootResolved: true,
            timestamp: 't',
            toolVersion: '0',
            inspected: [],
            skipped: [],
          },
        },
        {
          findings: [],
          metadata: {
            target: '/b',
            targetRootResolved: false,
            timestamp: 't',
            toolVersion: '0',
            inspected: [],
            skipped: [],
          },
        },
      ]),
    ) as unknown;
    expect(validate(doc)).toBe(true);
  });

  it('uses repository-relative URIs that never contain the local path', () => {
    const doc = JSON.parse(sarif) as SarifShape;
    const uris = doc.runs[0]?.results.flatMap(
      (r) => r.locations?.map((l) => l.physicalLocation.artifactLocation) ?? [],
    );
    expect(uris?.length).toBeGreaterThan(0);
    for (const uri of uris ?? []) {
      expect(uri.uriBaseId).toBe('SRCROOT');
      expect(uri.uri).not.toContain('file:');
    }
    expect(sarif).not.toContain(dir);
  });

  it('gives every result a stable fingerprint and every rule a security-severity', () => {
    const run = (JSON.parse(sarif) as SarifShape).runs[0];
    for (const result of run?.results ?? []) {
      expect(result.partialFingerprints['chaperoneFingerprint/v1']).toMatch(/^[0-9a-f]{64}$/);
    }
    // A rule for every check that ran, not only those that fired.
    expect(run?.tool.driver.rules).toHaveLength(ALL_CHECKS.length);
    for (const rule of run?.tool.driver.rules ?? []) {
      expect(rule.properties['security-severity']).toMatch(/^\d+\.\d$/);
    }
    expect(run?.invocations[0]?.executionSuccessful).toBe(true);
  });

  it('emits related locations for skills with several call sites', () => {
    const run = (JSON.parse(sarif) as SarifShape).runs[0];
    expect(run?.results.some((r) => (r.relatedLocations?.length ?? 0) > 0)).toBe(true);
  });

  it('keeps the same fingerprint when the install moves', () => {
    const moved = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sarif-moved-'));
    try {
      cpSync(dir, moved, { recursive: true });
      const { model, targetRootResolved } = discoverAgent({ targetPath: moved });
      const { findings } = runChecks(model, ALL_CHECKS);
      const again = formatSarifReport(findings, {
        target: model.targetRoot,
        targetRootResolved,
        timestamp: 't',
        toolVersion: '0.0.0',
        inspected: [],
        skipped: [],
        sourceRoot: model.git.gitRootPath ?? model.targetRoot,
      });
      const prints = (text: string): string[] =>
        (JSON.parse(text) as SarifShape).runs[0]?.results
          .map((r) => r.partialFingerprints['chaperoneFingerprint/v1'] ?? '')
          .sort() ?? [];
      expect(prints(again)).toEqual(prints(sarif));
    } finally {
      rmSync(moved, { recursive: true, force: true });
    }
  });
});
