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

    expect(findingFingerprint(a, '/')).toBe(findingFingerprint(b, '/'));
  });

  // PROPOSED_FIXES.md 2.7 — message wording changes between Chaperone
  // versions (and some messages embed variable data), so it must not
  // resurface an otherwise-unchanged finding.
  it('is stable across a differing message', () => {
    const a = makeFinding({ message: 'first wording' });
    const b = makeFinding({ message: 'reworded in a later release' });

    expect(findingFingerprint(a, '/')).toBe(findingFingerprint(b, '/'));
  });

  it('differs when the detail differs', () => {
    const a = makeFinding({ location: { filePath: '/f.yaml', line: null, detail: 'llm.api_key' } });
    const b = makeFinding({
      location: { filePath: '/f.yaml', line: null, detail: 'gateway.token' },
    });

    expect(findingFingerprint(a, '/')).not.toBe(findingFingerprint(b, '/'));
  });

  it('is the same for the same file under two different target roots', () => {
    const a = makeFinding({
      location: { filePath: '/home/me/clawd/config.yaml', line: null, detail: 'x' },
    });
    const b = makeFinding({
      location: { filePath: '/home/runner/work/clawd/config.yaml', line: null, detail: 'x' },
    });

    expect(findingFingerprint(a, '/home/me/clawd')).toBe(
      findingFingerprint(b, '/home/runner/work/clawd'),
    );
  });

  it('keeps a path outside the target root absolute rather than climbing out with ../', () => {
    const outside = makeFinding({
      location: { filePath: '/var/log/agent.log', line: null, detail: 'x' },
    });
    const elsewhere = makeFinding({
      location: { filePath: '/srv/var/log/agent.log', line: null, detail: 'x' },
    });

    expect(findingFingerprint(outside, '/home/me/clawd')).not.toBe(
      findingFingerprint(elsewhere, '/srv/clawd'),
    );
  });

  it('leaves a null file path and a non-absolute pseudo-path alone', () => {
    const noPath = makeFinding({ location: { filePath: null, line: null, detail: 'x' } });
    const pseudo = makeFinding({
      location: { filePath: 'package.json#scripts.postinstall', line: null, detail: 'x' },
    });

    expect(findingFingerprint(noPath, '/a')).toBe(findingFingerprint(noPath, '/b'));
    expect(findingFingerprint(pseudo, '/a')).toBe(findingFingerprint(pseudo, '/b'));
  });

  it('differs when the check ID differs', () => {
    const a = makeFinding({ checkId: 'CHAP-SEC-001' });
    const b = makeFinding({ checkId: 'CHAP-SEC-002' });

    expect(findingFingerprint(a, '/')).not.toBe(findingFingerprint(b, '/'));
  });
});

describe('findNewFindings', () => {
  it('excludes findings already present in the baseline', () => {
    const shared = makeFinding({ checkId: 'CHAP-SEC-001' });
    const baseline = buildScanReport([shared], METADATA);
    const current = [shared, makeFinding({ checkId: 'CHAP-NET-001' })];

    const result = findNewFindings(current, baseline, METADATA.target);

    expect(result).toHaveLength(1);
    expect(result[0]?.checkId).toBe('CHAP-NET-001');
  });

  it('treats every finding as new when the baseline is empty', () => {
    const baseline = buildScanReport([], METADATA);
    const current = [makeFinding()];

    expect(findNewFindings(current, baseline, METADATA.target)).toEqual(current);
  });

  it('returns nothing new when current findings exactly match the baseline', () => {
    const findings = [
      makeFinding({ checkId: 'CHAP-SEC-001' }),
      makeFinding({ checkId: 'CHAP-NET-001' }),
    ];
    const baseline = buildScanReport(findings, METADATA);

    expect(findNewFindings(findings, baseline, METADATA.target)).toEqual([]);
  });

  it('is unaffected by a resolved finding present only in the baseline', () => {
    const resolved = makeFinding({ checkId: 'CHAP-SEC-999' });
    const baseline = buildScanReport([resolved], METADATA);

    expect(findNewFindings([], baseline, METADATA.target)).toEqual([]);
  });

  it('matches an unchanged install scanned from a different directory (the copy-and-rescan repro)', () => {
    const at = (root: string): Finding[] => [
      makeFinding({
        location: { filePath: `${root}/config.yaml`, line: 6, detail: 'llm.api_key' },
      }),
      makeFinding({
        checkId: 'CHAP-AGY-001',
        location: {
          filePath: `${root}/skills/shell-runner/package.json`,
          line: null,
          detail: 'shell-runner',
        },
      }),
    ];
    const baseline = buildScanReport(at('/Users/me/clawd'), {
      ...METADATA,
      target: '/Users/me/clawd',
    });

    expect(
      findNewFindings(at('/home/runner/work/clawd'), baseline, '/home/runner/work/clawd'),
    ).toEqual([]);
  });

  it('still reports a genuinely new finding after the move', () => {
    const baseline = buildScanReport(
      [
        makeFinding({
          location: { filePath: '/old/config.yaml', line: null, detail: 'llm.api_key' },
        }),
      ],
      { ...METADATA, target: '/old' },
    );
    const added = makeFinding({
      location: { filePath: '/new/config.yaml', line: null, detail: 'channels.telegram.bot_token' },
    });
    const current = [
      makeFinding({
        location: { filePath: '/new/config.yaml', line: null, detail: 'llm.api_key' },
      }),
      added,
    ];

    expect(findNewFindings(current, baseline, '/new')).toEqual([added]);
  });
});
