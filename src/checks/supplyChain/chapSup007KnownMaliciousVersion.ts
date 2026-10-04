import path from 'node:path';
import type { Check } from '../../engine/types.js';
import type { Finding, Skill } from '../../model/types.js';
import { activeMaliciousDb } from '../shared/advisoryDb.js';
import type { MaliciousDbEntry } from '../shared/maliciousDb.js';
import { compareVersions, extractBaseVersion } from '../shared/semver.js';

const ID = 'CHAP-SUP-007';
const TITLE = 'Known-malicious package version';
const OWASP = 'LLM05: Supply Chain';
const REMEDIATION =
  'Remove the package or move to a version published before or after the compromise, delete node_modules and reinstall from a clean lockfile, and rotate any credentials available to the machine that ran it: malicious install scripts typically steal tokens and keys.';

/** Whether `version` is one an advisory lists as malicious. */
export function isMaliciousVersion(entry: MaliciousDbEntry, version: string): boolean {
  if (entry.versions.includes('*') || entry.versions.includes(version)) {
    return true;
  }
  const base = extractBaseVersion(version);
  return (
    base !== null &&
    entry.ranges.some(
      (range) =>
        compareVersions(base, range.introduced) >= 0 &&
        (range.fixed === null || compareVersions(base, range.fixed) < 0),
    )
  );
}

/**
 * Versions to check: the lockfile's resolved versions when there is one.
 * Without one, only an exact pin (`"5.6.1"`, `"=5.6.1"`) is a known
 * version; a range like `^5.6.0` could resolve to anything, so it only
 * matches advisories that cover every version of a package.
 */
function versionsToCheck(
  skill: Skill,
): Array<{ name: string; version: string | null; how: string }> {
  const deps = skill.dependencies;
  if (deps.resolved !== null && deps.lockfilePath !== null) {
    const lockfile = path.basename(deps.lockfilePath);
    return deps.resolved.map(({ name, version }) => ({
      name,
      version,
      how: `${name}@${version} (${name in deps.versionsByName ? 'direct' : 'transitive'}, resolved by ${lockfile})`,
    }));
  }
  return Object.entries(deps.versionsByName).map(([name, specifier]) => {
    const exact = /^=?v?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)$/.exec(specifier.trim())?.[1] ?? null;
    return { name, version: exact, how: `${name}@${specifier}` };
  });
}

/** Flags a dependency version that OSV lists as malicious (PROPOSED_FIXES.md 3.5). */
export const chapSup007KnownMaliciousVersion: Check = {
  id: ID,
  title: TITLE,
  severity: 'critical',
  category: 'supply-chain',
  owasp: OWASP,
  detects:
    'A skill dependency, direct or transitive, at a version OSV lists as malicious: a compromised maintainer account, protestware, or a package that was malware from the start.',
  heuristic:
    'Lockfile-resolved versions (or exact `package.json` pins when there is no lockfile) are matched against `shared/maliciousDb.ts`: advisories OSV classifies as malware (MAL- ids, CWE-506, or a summary naming malware or malicious code) for packages with a history of compromise, plus any loaded with `--vuln-db`. A range specifier without a lockfile only matches a package that is malicious in every version. npm dependencies only.',
  remediation: REMEDIATION,
  run(model) {
    const db = activeMaliciousDb();
    const findings: Finding[] = [];
    for (const skill of model.skills) {
      if (skill.dependencies.ecosystem !== 'npm') {
        continue;
      }
      const reported = new Set<string>();
      for (const { name, version, how } of versionsToCheck(skill)) {
        const matches = db.filter(
          (entry) =>
            entry.packageName === name &&
            (version === null ? entry.versions.includes('*') : isMaliciousVersion(entry, version)),
        );
        const key = `${name}@${version ?? '*'}`;
        if (matches.length === 0 || reported.has(key)) {
          continue;
        }
        reported.add(key);
        const ids = [...new Set(matches.map((m) => m.id))];
        findings.push({
          checkId: ID,
          title: TITLE,
          severity: 'critical',
          category: 'supply-chain',
          owasp: OWASP,
          message: `Skill '${skill.name}' depends on ${how}, a known-malicious version (${ids.join(', ')}: "${matches[0]?.summary ?? ''}").`,
          location: {
            filePath:
              skill.dependencies.lockfilePath ?? skill.dependencies.manifestPath ?? skill.dir,
            line: null,
            detail: key,
          },
          remediation: REMEDIATION,
        });
      }
    }
    return findings;
  },
};
