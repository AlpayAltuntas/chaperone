import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { loadVulnDbFile, resetVulnDb } from '../../src/checks/shared/advisoryDb.js';
import { advisoriesFromOsvExport, isMaliciousAdvisory } from '../../src/checks/shared/osv.js';
import { chapSup003KnownVulnerableDependencies } from '../../src/checks/supplyChain/chapSup003KnownVulnerableDependencies.js';
import { chapSup007KnownMaliciousVersion } from '../../src/checks/supplyChain/chapSup007KnownMaliciousVersion.js';
import { run } from '../../src/cli.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { parsePackageLock, parsePnpmLock, parseYarnLock } from '../../src/discovery/lockfiles.js';

// PROPOSED_FIXES.md 3.5.
describe('lockfile parsers', () => {
  it('reads package-lock v3 packages, including nested and scoped ones', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'skill', dependencies: { lodash: '^4.17.15' } },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/a/node_modules/minimist': { version: '1.2.5' },
        'node_modules/@scope/pkg': { version: '2.0.0' },
        'node_modules/linked': { link: true },
      },
    });
    expect(parsePackageLock(lock)).toEqual([
      { name: 'lodash', version: '4.17.21' },
      { name: 'minimist', version: '1.2.5' },
      { name: '@scope/pkg', version: '2.0.0' },
    ]);
  });

  it('falls back to package-lock v1 dependencies', () => {
    const lock = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } } },
    });
    expect(parsePackageLock(lock)).toEqual([
      { name: 'a', version: '1.0.0' },
      { name: 'b', version: '2.0.0' },
    ]);
  });

  it('reads yarn.lock v1', () => {
    const lock = [
      '# yarn lockfile v1',
      '',
      '"@scope/pkg@^1.0.0", "@scope/pkg@^1.1.0":',
      '  version "1.2.0"',
      '',
      'chalk@^5.6.0:',
      '  version "5.6.1"',
      '  resolved "https://registry.yarnpkg.com/chalk/-/chalk-5.6.1.tgz"',
      '',
    ].join('\n');
    expect(parseYarnLock(lock)).toEqual([
      { name: '@scope/pkg', version: '1.2.0' },
      { name: 'chalk', version: '5.6.1' },
    ]);
  });

  it('reads pnpm-lock v6, v9, and v5 keys', () => {
    const lock =
      "lockfileVersion: '9.0'\npackages:\n  /debug@4.4.2:\n    resolution: {}\n  chalk@5.6.1(peer@1.0.0):\n    resolution: {}\n  /ms/2.1.3:\n    resolution: {}\n";
    expect(parsePnpmLock(lock)).toEqual([
      { name: 'debug', version: '4.4.2' },
      { name: 'chalk', version: '5.6.1' },
      { name: 'ms', version: '2.1.3' },
    ]);
  });
});

describe('OSV classification', () => {
  it.each([
    [{ id: 'MAL-2025-1', summary: 'Malicious code in x' }, true],
    [{ id: 'GHSA-a', summary: 'debug@4.4.2 contains malware after npm account takeover' }, true],
    [{ id: 'GHSA-b', summary: 'Something', database_specific: { cwe_ids: ['CWE-506'] } }, true],
    [{ id: 'GHSA-c', summary: 'Malicious WebSocket 64-bit length overflows parser' }, false],
    [{ id: 'GHSA-d', summary: 'denial of service via malicious Content-Type' }, false],
  ])('%j -> %s', (vuln, expected) => {
    expect(isMaliciousAdvisory(vuln)).toBe(expected);
  });

  it('extracts both kinds of advisory from an OSV export', () => {
    const exported = {
      vulns: [
        {
          id: 'GHSA-x',
          summary: 'Prototype pollution in leftpad2',
          database_specific: { severity: 'HIGH' },
          affected: [
            {
              package: { name: 'leftpad2', ecosystem: 'npm' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }],
            },
          ],
        },
        {
          id: 'MAL-x',
          summary: 'Malicious code in evilpkg',
          affected: [
            {
              package: { name: 'evilpkg', ecosystem: 'npm' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
            },
          ],
        },
        { id: 'PYSEC-1', affected: [{ package: { name: 'x', ecosystem: 'PyPI' } }] },
        'not a record',
      ],
    };
    const { vulns, malicious } = advisoriesFromOsvExport(exported);
    expect(vulns.map((v) => [v.packageName, v.fixed])).toEqual([['leftpad2', '1.0.1']]);
    expect(malicious.map((m) => [m.packageName, m.versions])).toEqual([['evilpkg', ['*']]]);
  });
});

describe('CHAP-SUP-003 / CHAP-SUP-007 against lockfiles', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-supply-'));
    writeFileSync(path.join(dir, 'config.yaml'), 'llm: {}\n');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    resetVulnDb();
  });

  function skill(name: string, deps: Record<string, string>, lock?: object): void {
    const skillDir = path.join(dir, 'skills', name);
    mkdirSync(skillDir, { recursive: true });
    writeFileSync(
      path.join(skillDir, 'package.json'),
      JSON.stringify({ name, version: '1.0.0', dependencies: deps }),
    );
    if (lock !== undefined) {
      writeFileSync(path.join(skillDir, 'package-lock.json'), JSON.stringify(lock));
    }
  }

  function lockOf(packages: Record<string, string>): object {
    return {
      lockfileVersion: 3,
      packages: Object.fromEntries(
        Object.entries(packages).map(([n, v]) => [`node_modules/${n}`, { version: v }]),
      ),
    };
  }

  it('uses the lockfile: a patched resolution is clean even if the specifier floor is vulnerable', () => {
    skill('patched', { lodash: '^4.17.15' }, lockOf({ lodash: '4.18.0' }));
    const { model } = discoverAgent({ targetPath: dir });
    expect(chapSup003KnownVulnerableDependencies.run(model)).toEqual([]);
  });

  it('finds a vulnerable transitive dependency in the lockfile', () => {
    skill('transitive', { foo: '^1.0.0' }, lockOf({ foo: '1.0.0', minimist: '1.2.5' }));
    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSup003KnownVulnerableDependencies.run(model);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain(
      'minimist@1.2.5, a transitive dependency resolved by package-lock.json',
    );
    expect(findings[0]?.location.filePath).toMatch(/package-lock\.json$/);
  });

  it('reports a compromised version resolved by the lockfile as critical', () => {
    skill('compromised', { chalk: '^5.6.0' }, lockOf({ chalk: '5.6.1' }));
    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSup007KnownMaliciousVersion.run(model);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: 'critical',
      location: { detail: 'chalk@5.6.1' },
    });
  });

  it('without a lockfile, matches an exact pin and an always-malicious package, not a range', () => {
    skill('pinned', { debug: '4.4.2', 'flatmap-stream': '^0.1.0', chalk: '^5.6.0' });
    const { model } = discoverAgent({ targetPath: dir });
    expect(
      chapSup007KnownMaliciousVersion
        .run(model)
        .map((f) => f.location.detail)
        .sort(),
    ).toEqual(['debug@4.4.2', 'flatmap-stream@*']);
  });

  it('matches advisories loaded with --vuln-db', () => {
    skill('custom', { leftpad2: '1.0.0' });
    const file = path.join(dir, 'osv.json');
    writeFileSync(
      file,
      JSON.stringify([
        {
          id: 'GHSA-custom',
          summary: 'Prototype pollution in leftpad2',
          database_specific: { severity: 'CRITICAL' },
          affected: [
            {
              package: { name: 'leftpad2', ecosystem: 'npm' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }],
            },
          ],
        },
      ]),
    );
    expect(loadVulnDbFile(file)).toBe(1);
    const { model } = discoverAgent({ targetPath: dir });
    expect(chapSup003KnownVulnerableDependencies.run(model)).toMatchObject([
      { severity: 'critical' },
    ]);
  });
});

describe('cli --vuln-db and the advisory header', () => {
  let logSpy: MockInstance<typeof console.log>;
  let originalExitCode: typeof process.exitCode;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    originalExitCode = process.exitCode;
  });

  afterEach(() => {
    logSpy.mockRestore();
    process.exitCode = originalExitCode;
    resetVulnDb();
  });

  it('shows the snapshot date and the extra file in the JSON report', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-vulndb-cli-'));
    try {
      const file = path.join(dir, 'osv.json');
      writeFileSync(file, JSON.stringify({ vulns: [] }));
      run([
        'node',
        'chaperone',
        'scan',
        path.join('test', 'fixtures', 'clean-agent'),
        '--format',
        'json',
        '--vuln-db',
        file,
      ]);
      const report = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as {
        advisoryData: { snapshotDate: string; extraFile: string | null; extraAdvisories: number };
      };
      expect(report.advisoryData.snapshotDate).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(report.advisoryData.extraFile).toBe(file);
      expect(report.advisoryData.extraAdvisories).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
