import { describe, expect, it } from 'vitest';
import {
  coversEveryVersion,
  diffAdvisoryData,
  formatDeltaMarkdown,
  hasDataChanges,
  type AdvisorySnapshot,
} from '../../scripts/vulnDbDelta.js';
import type { MaliciousDbEntry } from '../../src/checks/shared/maliciousDb.js';
import type { VulnDbEntry } from '../../src/checks/shared/vulnDb.js';

// Roadmap R6.1: the summary on the scheduled data-refresh PR.
const vuln = (packageName: string, id: string): VulnDbEntry => ({
  packageName,
  id,
  aliases: [],
  summary: `${id} in ${packageName}`,
  severity: 'high',
  introduced: '0',
  fixed: '2.0.0',
});

const malware = (
  packageName: string,
  id: string,
  versions: string[],
  ranges: MaliciousDbEntry['ranges'] = [],
): MaliciousDbEntry => ({
  packageName,
  id,
  summary: `Malicious code in ${packageName}`,
  versions,
  ranges,
});

const before: AdvisorySnapshot = {
  generatedAt: '2026-10-04T00:00:00.000Z',
  vulns: [vuln('lodash', 'GHSA-a'), vuln('axios', 'GHSA-b')],
  malicious: [malware('chalk', 'MAL-1', ['5.6.1'])],
};

describe('diffAdvisoryData', () => {
  it('reports counts, per-package changes, and added or removed malware', () => {
    const after: AdvisorySnapshot = {
      generatedAt: '2026-11-01T00:00:00.000Z',
      vulns: [vuln('lodash', 'GHSA-a'), vuln('lodash', 'GHSA-c'), vuln('axios', 'GHSA-b')],
      malicious: [malware('debug', 'MAL-2', ['4.4.2']), malware('evilpkg', 'MAL-3', ['*'])],
    };

    const delta = diffAdvisoryData(before, after);

    expect(delta).toMatchObject({
      vulnsBefore: 2,
      vulnsAfter: 3,
      maliciousBefore: 1,
      maliciousAfter: 2,
    });
    expect(delta.packageChanges).toEqual([
      { packageName: 'chalk', before: 1, after: 0 },
      { packageName: 'debug', before: 0, after: 1 },
      { packageName: 'evilpkg', before: 0, after: 1 },
      { packageName: 'lodash', before: 1, after: 2 },
    ]);
    expect(delta.addedMalicious.map((e) => e.id)).toEqual(['MAL-2', 'MAL-3']);
    expect(delta.removedMalicious.map((e) => e.id)).toEqual(['MAL-1']);
    expect(delta.broadMalicious.map((e) => e.id)).toEqual(['MAL-3']);
  });

  it('reports nothing when only the timestamp changed', () => {
    const after = { ...before, generatedAt: '2026-11-01T00:00:00.000Z' };
    expect(hasDataChanges(before, after)).toBe(false);
    expect(diffAdvisoryData(before, after).packageChanges).toEqual([]);
  });

  it('detects a changed advisory even when counts are equal', () => {
    const after = {
      ...before,
      vulns: [vuln('lodash', 'GHSA-a'), { ...vuln('axios', 'GHSA-b'), fixed: '3.0.0' }],
    };
    expect(hasDataChanges(before, after)).toBe(true);
  });
});

describe('coversEveryVersion', () => {
  it.each([
    [malware('p', 'M', ['*']), true],
    [malware('p', 'M', [], [{ introduced: '0', fixed: null }]), true],
    [malware('p', 'M', ['1.0.0']), false],
    [malware('p', 'M', [], [{ introduced: '0', fixed: '1.2.0' }]), false],
    [malware('p', 'M', [], [{ introduced: '1.0.0', fixed: null }]), false],
  ])('%j -> %s', (entry, expected) => {
    expect(coversEveryVersion(entry)).toBe(expected);
  });
});

describe('formatDeltaMarkdown', () => {
  it('warns about every-version entries and includes the review checklist', () => {
    const after: AdvisorySnapshot = {
      ...before,
      generatedAt: '2026-11-01T00:00:00.000Z',
      malicious: [...before.malicious, malware('lodash', 'MAL-9', ['*'])],
    };

    const markdown = formatDeltaMarkdown(diffAdvisoryData(before, after));

    expect(markdown).toContain('| Known-malicious entries | 1 | 2 | +1 |');
    expect(markdown).toContain('> [!WARNING]');
    expect(markdown).toContain('- `lodash`: MAL-9');
    expect(markdown).toContain('- [ ] CI is green on this PR');
    expect(markdown).toContain('Never auto-merge it.');
  });

  it('omits the warning when no entry covers every version, and escapes table cells', () => {
    const after: AdvisorySnapshot = {
      ...before,
      malicious: [
        ...before.malicious,
        { ...malware('x', 'MAL-5', ['1.0.0']), summary: 'pipe | in\nsummary' },
      ],
    };

    const markdown = formatDeltaMarkdown(diffAdvisoryData(before, after));

    expect(markdown).not.toContain('[!WARNING]');
    expect(markdown).toContain('pipe \\| in summary');
  });

  it('says so when nothing changed', () => {
    const markdown = formatDeltaMarkdown(diffAdvisoryData(before, before));
    expect(markdown).toContain('No package changed.');
    expect(markdown).toContain('### New known-malicious entries\n\nNone.');
  });
});
