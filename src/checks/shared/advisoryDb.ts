import { readFileSync } from 'node:fs';
import { MALICIOUS_DB, type MaliciousDbEntry } from './maliciousDb.js';
import { advisoriesFromOsvExport } from './osv.js';
import { VULN_DB, VULN_DB_GENERATED_AT, type VulnDbEntry } from './vulnDb.js';

// The advisory data CHAP-SUP-003/007 match against: the bundled OSV
// snapshot, plus any advisories loaded with `--vuln-db` (PROPOSED_FIXES.md
// 3.5). Process-wide, like an environment setting: checks stay pure
// functions of the model, and the CLI loads the file once before a scan.

let extraVulns: readonly VulnDbEntry[] = [];
let extraMalicious: readonly MaliciousDbEntry[] = [];
let extraSource: string | null = null;

export function activeVulnDb(): readonly VulnDbEntry[] {
  return extraVulns.length === 0 ? VULN_DB : [...VULN_DB, ...extraVulns];
}

export function activeMaliciousDb(): readonly MaliciousDbEntry[] {
  return extraMalicious.length === 0 ? MALICIOUS_DB : [...MALICIOUS_DB, ...extraMalicious];
}

export interface AdvisoryDataInfo {
  snapshotDate: string;
  bundledAdvisories: number;
  extraFile: string | null;
  extraAdvisories: number;
}

/** What advisory data a scan used, for the report header. */
export function advisoryDataInfo(): AdvisoryDataInfo {
  return {
    snapshotDate: VULN_DB_GENERATED_AT,
    bundledAdvisories: VULN_DB.length + MALICIOUS_DB.length,
    extraFile: extraSource,
    extraAdvisories: extraVulns.length + extraMalicious.length,
  };
}

/** Loads an OSV JSON export (array, `{vulns: [...]}`, or one record) as extra advisories; throws on unreadable or unparseable input. */
export function loadVulnDbFile(file: string): number {
  const parsed = JSON.parse(readFileSync(file, 'utf8')) as unknown;
  const { vulns, malicious } = advisoriesFromOsvExport(parsed);
  extraVulns = vulns;
  extraMalicious = malicious;
  extraSource = file;
  return vulns.length + malicious.length;
}

/** Drops loaded extra advisories (tests, and a library caller scanning twice). */
export function resetVulnDb(): void {
  extraVulns = [];
  extraMalicious = [];
  extraSource = null;
}
