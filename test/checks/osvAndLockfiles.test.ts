import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  extractSimpleRange,
  maliciousVersions,
  normalizeSeverity,
  vulnEntriesFrom,
  type OsvVuln,
} from '../../src/checks/shared/osv.js';
import { isMaliciousVersion } from '../../src/checks/supplyChain/chapSup007KnownMaliciousVersion.js';
import { readLockfile } from '../../src/discovery/lockfiles.js';
import { applyFixPlan } from '../../src/fix/apply.js';

const npm = (name: string, extra: object): NonNullable<OsvVuln['affected']> => [
  { package: { name, ecosystem: 'npm' }, ...extra },
];

describe('osv helpers', () => {
  it.each([
    ['CRITICAL', 'critical'],
    ['high', 'high'],
    ['MODERATE', 'medium'],
    ['LOW', 'low'],
    ['UNKNOWN', null],
    [undefined, null],
  ])('normalizeSeverity(%s) -> %s', (input, expected) => {
    expect(normalizeSeverity(input)).toBe(expected);
  });

  it('extracts only an npm SEMVER range with both bounds for the named package', () => {
    const affected = {
      package: { name: 'p', ecosystem: 'npm' },
      ranges: [
        { type: 'ECOSYSTEM', events: [] },
        { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }] },
      ],
    };
    expect(extractSimpleRange(affected, 'p')).toEqual({ introduced: '1.0.0', fixed: '1.2.0' });
    expect(extractSimpleRange(affected, 'other')).toBeNull();
    expect(
      extractSimpleRange(
        {
          ...affected,
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { last_affected: '1.0.0' }] }],
        },
        'p',
      ),
    ).toBeNull();
  });

  it('reads malicious versions from lists, last_affected, open ranges, and all-versions ranges', () => {
    const vuln = (affected: NonNullable<OsvVuln['affected']>): OsvVuln => ({
      id: 'MAL-1',
      affected,
    });
    expect(maliciousVersions(vuln(npm('p', { versions: ['1.0.1', '1.0.2'] })), 'p')).toEqual({
      versions: ['1.0.1', '1.0.2'],
      ranges: [],
    });
    expect(
      maliciousVersions(
        vuln(
          npm('p', {
            ranges: [
              { type: 'SEMVER', events: [{ introduced: '2.0.0' }, { last_affected: '2.0.3' }] },
            ],
          }),
        ),
        'p',
      ),
    ).toEqual({ versions: ['2.0.0', '2.0.3'], ranges: [] });
    expect(
      maliciousVersions(
        vuln(npm('p', { ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] })),
        'p',
      ),
    ).toEqual({ versions: ['*'], ranges: [] });
    expect(
      maliciousVersions(
        vuln(npm('p', { ranges: [{ type: 'SEMVER', events: [{ introduced: '3.0.0' }] }] })),
        'p',
      ),
    ).toEqual({ versions: [], ranges: [{ introduced: '3.0.0', fixed: null }] });
    expect(
      maliciousVersions(vuln(npm('p', { ranges: [{ type: 'GIT', events: [] }] })), 'p'),
    ).toBeNull();
    expect(maliciousVersions(vuln(npm('q', { versions: ['1.0.0'] })), 'p')).toBeNull();
  });

  it('skips advisories with no usable severity or range', () => {
    const vulns: OsvVuln[] = [
      {
        id: 'A',
        database_specific: { severity: 'NONE' },
        affected: npm('p', {
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }],
        }),
      },
      { id: 'B', database_specific: { severity: 'HIGH' }, affected: npm('p', { ranges: [] }) },
      {
        id: 'C',
        summary: 'x',
        database_specific: { severity: 'HIGH' },
        affected: npm('p', {
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }],
        }),
      },
    ];
    expect(vulnEntriesFrom(vulns, 'p').map((v) => v.id)).toEqual(['C']);
  });
});

describe('isMaliciousVersion', () => {
  const entry = {
    packageName: 'p',
    id: 'X',
    summary: 's',
    versions: ['1.0.0-beta.1'],
    ranges: [{ introduced: '2.0.0', fixed: null }],
  };
  it.each([
    ['1.0.0-beta.1', true],
    ['2.5.0', true],
    ['1.9.9', false],
    ['not-a-version', false],
  ])('%s -> %s', (version, expected) => {
    expect(isMaliciousVersion(entry, version)).toBe(expected);
  });

  it('matches every version for a whole-package entry', () => {
    expect(isMaliciousVersion({ ...entry, versions: ['*'], ranges: [] }, '0.0.1')).toBe(true);
  });
});

describe('readLockfile and applyFixPlan', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-lock-apply-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('dispatches by file name and returns null for unreadable, unparseable, or unknown files', () => {
    writeFileSync(path.join(dir, 'yarn.lock'), 'ms@^2.0.0:\n  version "2.1.3"\n');
    writeFileSync(path.join(dir, 'pnpm-lock.yaml'), 'packages:\n  /ms@2.1.3: {}\n');
    writeFileSync(path.join(dir, 'npm-shrinkwrap.json'), '{ broken');
    writeFileSync(path.join(dir, 'bun.lockb'), 'x');
    expect(readLockfile(path.join(dir, 'yarn.lock'))).toEqual([{ name: 'ms', version: '2.1.3' }]);
    expect(readLockfile(path.join(dir, 'pnpm-lock.yaml'))).toEqual([
      { name: 'ms', version: '2.1.3' },
    ]);
    expect(readLockfile(path.join(dir, 'npm-shrinkwrap.json'))).toBeNull();
    expect(readLockfile(path.join(dir, 'bun.lockb'))).toBeNull();
    expect(readLockfile(path.join(dir, 'missing.json'))).toBeNull();
  });

  it('appends only missing lines, adding a newline when the file lacks one', () => {
    const file = path.join(dir, '.gitignore');
    writeFileSync(file, 'a');
    const messages = applyFixPlan({
      checkId: 'T',
      changes: [],
      notes: [],
      actions: [
        { kind: 'append-lines', filePath: file, lines: ['a', 'b'] },
        { kind: 'append-lines', filePath: file, lines: ['b'] },
        { kind: 'write-file', filePath: path.join(dir, 'new.txt'), content: 'x', mode: 0o600 },
      ],
    });
    expect(readFileSync(file, 'utf8')).toBe('a\nb\n');
    expect(messages[1]).toContain('already has every line');
  });
});
