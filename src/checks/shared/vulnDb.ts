// GENERATED FILE — do not hand-edit. Run `npm run refresh:vulndb` to
// regenerate (see scripts/refreshVulnDb.ts). Source: OSV.dev
// (https://osv.dev), queried out-of-band, never during a scan
// (improvement_plan.md 1.15/Phase 18).
//
// Generated: 2026-09-19T20:47:58.024Z
// Tracked packages: lodash, minimist

export interface VulnDbEntry {
  packageName: string;
  id: string;
  aliases: readonly string[];
  summary: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Vulnerable range lower bound (inclusive). */
  introduced: string;
  /** Vulnerable range upper bound (exclusive) — the first patched version. */
  fixed: string;
}

/**
 * A small, curated offline snapshot of known npm-package vulnerabilities
 * — CHAP-SUP-003 matches a skill's declared dependency versions against
 * this, entirely offline. Not the whole OSV database (many GB); a
 * deliberately scoped set of well-known packages, refreshed periodically
 * out-of-band. See DECISIONS.md, Phase 18.
 */
export const VULN_DB: readonly VulnDbEntry[] = [
  {
    packageName: 'lodash',
    id: 'GHSA-29mw-wpgm-hmr9',
    aliases: ['CVE-2020-28500'],
    summary: 'Regular Expression Denial of Service (ReDoS) in lodash',
    severity: 'medium',
    introduced: '4.0.0',
    fixed: '4.17.21',
  },
  {
    packageName: 'lodash',
    id: 'GHSA-35jh-r3h4-6jhm',
    aliases: ['CVE-2021-23337', 'CVE-2026-4800', 'GHSA-r5fr-rjxr-66jc'],
    summary: 'Command Injection in lodash',
    severity: 'high',
    introduced: '0',
    fixed: '4.17.21',
  },
  {
    packageName: 'lodash',
    id: 'GHSA-4xc9-xhrj-v574',
    aliases: ['CVE-2018-16487'],
    summary: 'Prototype Pollution in lodash',
    severity: 'high',
    introduced: '0',
    fixed: '4.17.11',
  },
  {
    packageName: 'lodash',
    id: 'GHSA-f23m-r3pf-42rh',
    aliases: ['CVE-2025-13465', 'CVE-2026-2950', 'GHSA-xxjr-mmjv-4gpg'],
    summary:
      'lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit`',
    severity: 'medium',
    introduced: '0',
    fixed: '4.18.0',
  },
  {
    packageName: 'lodash',
    id: 'GHSA-fvqr-27wr-82fm',
    aliases: ['CVE-2018-3721'],
    summary: 'Prototype Pollution in lodash',
    severity: 'medium',
    introduced: '0',
    fixed: '4.17.5',
  },
  {
    packageName: 'lodash',
    id: 'GHSA-jf85-cpcp-j695',
    aliases: ['CVE-2019-10744', 'SNYK-JS-LODASH-450202'],
    summary: 'Prototype Pollution in lodash',
    severity: 'critical',
    introduced: '0',
    fixed: '4.17.12',
  },
  {
    packageName: 'lodash',
    id: 'GHSA-p6mc-m468-83gw',
    aliases: ['CVE-2020-8203'],
    summary: 'Prototype Pollution in lodash',
    severity: 'high',
    introduced: '3.7.0',
    fixed: '4.17.19',
  },
  {
    packageName: 'lodash',
    id: 'GHSA-r5fr-rjxr-66jc',
    aliases: ['CVE-2021-23337', 'CVE-2026-4800', 'GHSA-35jh-r3h4-6jhm'],
    summary: 'lodash vulnerable to Code Injection via `_.template` imports key names',
    severity: 'high',
    introduced: '4.0.0',
    fixed: '4.18.0',
  },
  {
    packageName: 'lodash',
    id: 'GHSA-x5rq-j2xg-h7qm',
    aliases: ['CVE-2019-1010266', 'SNYK-JS-LODASH-73639'],
    summary: 'Regular Expression Denial of Service (ReDoS) in lodash',
    severity: 'medium',
    introduced: '4.7.0',
    fixed: '4.17.11',
  },
  {
    packageName: 'lodash',
    id: 'GHSA-xxjr-mmjv-4gpg',
    aliases: ['CVE-2025-13465', 'CVE-2026-2950', 'GHSA-f23m-r3pf-42rh'],
    summary: 'Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions',
    severity: 'medium',
    introduced: '4.0.0',
    fixed: '4.17.23',
  },
  {
    packageName: 'minimist',
    id: 'GHSA-vh95-rmgr-6w4m',
    aliases: ['CVE-2020-7598'],
    summary: 'Prototype Pollution in minimist',
    severity: 'medium',
    introduced: '0',
    fixed: '0.2.1',
  },
  {
    packageName: 'minimist',
    id: 'GHSA-xvch-5gv4-984h',
    aliases: ['CVE-2021-44906'],
    summary: 'Prototype Pollution in minimist',
    severity: 'critical',
    introduced: '1.0.0',
    fixed: '1.2.6',
  },
];
