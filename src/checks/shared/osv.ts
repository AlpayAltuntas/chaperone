import type { MaliciousDbEntry } from './maliciousDb.js';
import type { VulnDbEntry } from './vulnDb.js';

// OSV (https://osv.dev) record parsing, shared by the out-of-band refresh
// script (scripts/refreshVulnDb.ts) and `--vuln-db`, which loads a
// user-supplied OSV export at scan time (PROPOSED_FIXES.md 3.5). Keeps
// only what this project's simple range model can represent: an exact
// npm SEMVER range with `introduced` and `fixed`, or, for malware,
// explicit versions and ranges.

interface OsvPackage {
  name: string;
  ecosystem: string;
}

interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

interface OsvRange {
  type: string;
  events: OsvRangeEvent[];
}

interface OsvAffected {
  package?: OsvPackage;
  ranges?: OsvRange[];
  versions?: string[];
}

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: OsvAffected[];
}

export function normalizeSeverity(osvSeverity: string | undefined): VulnDbEntry['severity'] | null {
  switch ((osvSeverity ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return null;
  }
}

/** Extracts this project's simplified {introduced, fixed} shape from one OSV `affected` entry for the exact tracked package, or null if it doesn't fit that shape. */
export function extractSimpleRange(
  affected: OsvAffected,
  packageName: string,
): { introduced: string; fixed: string } | null {
  if (affected.package?.ecosystem !== 'npm' || affected.package.name !== packageName) {
    return null;
  }
  for (const range of affected.ranges ?? []) {
    if (range.type !== 'SEMVER') {
      continue;
    }
    const introducedEvent = range.events.find((e) => e.introduced !== undefined);
    const fixedEvent = range.events.find((e) => e.fixed !== undefined);
    if (introducedEvent?.introduced !== undefined && fixedEvent?.fixed !== undefined) {
      return { introduced: introducedEvent.introduced, fixed: fixedEvent.fixed };
    }
  }
  return null;
}

/**
 * Malware, as opposed to a vulnerability that merely mentions malicious
 * input: a MAL- id (the OpenSSF malicious-packages feed), CWE-506
 * "Embedded Malicious Code" on a GitHub advisory, or a summary that names
 * malware or malicious code/package/versions. "Malicious WebSocket frame
 * crashes the parser" is a denial-of-service bug and doesn't count.
 */
export function isMaliciousAdvisory(vuln: OsvVuln): boolean {
  return (
    vuln.id.startsWith('MAL-') ||
    (vuln.database_specific?.cwe_ids ?? []).includes('CWE-506') ||
    /\b(?:malware|backdoor(?:ed)?|malicious (?:code|package|version|versions|payload))\b/i.test(
      vuln.summary ?? '',
    )
  );
}

/** The malicious versions and ranges an advisory lists for a package; null when it lists neither. */
export function maliciousVersions(
  vuln: OsvVuln,
  packageName: string,
): Pick<MaliciousDbEntry, 'versions' | 'ranges'> | null {
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.ecosystem !== 'npm' || affected.package.name !== packageName) {
      continue;
    }
    const versions = [...(affected.versions ?? [])];
    const ranges: Array<{ introduced: string; fixed: string | null }> = [];
    for (const range of affected.ranges ?? []) {
      if (range.type !== 'SEMVER') {
        continue;
      }
      const introduced = range.events.find((e) => e.introduced !== undefined)?.introduced;
      const fixed = range.events.find((e) => e.fixed !== undefined)?.fixed ?? null;
      const lastAffected = range.events.find((e) => e.last_affected !== undefined)?.last_affected;
      if (introduced === undefined) {
        continue;
      }
      if (lastAffected !== undefined && fixed === null) {
        // `last_affected` is inclusive; record the endpoints as exact versions.
        versions.push(...(introduced === lastAffected ? [introduced] : [introduced, lastAffected]));
        continue;
      }
      if (introduced === '0' && fixed === null) {
        versions.push('*');
        continue;
      }
      ranges.push({ introduced, fixed });
    }
    if (versions.length > 0 || ranges.length > 0) {
      return { versions: [...new Set(versions)], ranges };
    }
  }
  return null;
}

export function maliciousEntriesFrom(
  vulns: readonly OsvVuln[],
  packageName: string,
): MaliciousDbEntry[] {
  const entries: MaliciousDbEntry[] = [];
  for (const vuln of vulns) {
    if (!isMaliciousAdvisory(vuln)) {
      continue;
    }
    const affected = maliciousVersions(vuln, packageName);
    if (affected !== null) {
      entries.push({ packageName, id: vuln.id, summary: vuln.summary ?? vuln.id, ...affected });
    }
  }
  return entries;
}

export function vulnEntriesFrom(vulns: readonly OsvVuln[], packageName: string): VulnDbEntry[] {
  const entries: VulnDbEntry[] = [];
  for (const vuln of vulns) {
    if (isMaliciousAdvisory(vuln)) {
      continue;
    }
    const severity = normalizeSeverity(vuln.database_specific?.severity);
    if (severity === null) {
      continue;
    }
    for (const affected of vuln.affected ?? []) {
      const range = extractSimpleRange(affected, packageName);
      if (range === null) {
        continue;
      }
      entries.push({
        packageName,
        id: vuln.id,
        aliases: vuln.aliases ?? [],
        summary: vuln.summary ?? vuln.id,
        severity,
        introduced: range.introduced,
        fixed: range.fixed,
      });
      break; // one entry per vuln per package is enough signal
    }
  }
  return entries;
}

/**
 * Every npm advisory in a set of OSV records, for any package they name.
 * Accepts what OSV exports: an array of records, `{ "vulns": [...] }`, or
 * a single record.
 */
export function advisoriesFromOsvExport(parsed: unknown): {
  vulns: VulnDbEntry[];
  malicious: MaliciousDbEntry[];
} {
  const records: unknown[] = Array.isArray(parsed)
    ? parsed
    : typeof parsed === 'object' &&
        parsed !== null &&
        Array.isArray((parsed as { vulns?: unknown }).vulns)
      ? (parsed as { vulns: unknown[] }).vulns
      : [parsed];
  const vulns: VulnDbEntry[] = [];
  const malicious: MaliciousDbEntry[] = [];
  for (const record of records) {
    if (
      typeof record !== 'object' ||
      record === null ||
      typeof (record as { id?: unknown }).id !== 'string'
    ) {
      continue;
    }
    const vuln = record as OsvVuln;
    const names = new Set(
      (vuln.affected ?? [])
        .filter((a) => a.package?.ecosystem === 'npm')
        .map((a) => a.package?.name ?? ''),
    );
    for (const name of names) {
      if (name === '') {
        continue;
      }
      vulns.push(...vulnEntriesFrom([vuln], name));
      malicious.push(...maliciousEntriesFrom([vuln], name));
    }
  }
  return { vulns, malicious };
}
