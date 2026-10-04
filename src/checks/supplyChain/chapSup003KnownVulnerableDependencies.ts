import path from 'node:path';
import { severityRank } from '../../engine/severity.js';
import type { Check } from '../../engine/types.js';
import type { Finding, Severity, Skill } from '../../model/types.js';
import { activeVulnDb } from '../shared/advisoryDb.js';
import { extractBaseVersion, isVersionInRange } from '../shared/semver.js';
import type { VulnDbEntry } from '../shared/vulnDb.js';

const ID = 'CHAP-SUP-003';
const TITLE = 'Known-vulnerable dependency';
const OWASP = 'LLM05: Supply Chain';

function worstMatch(matches: readonly VulnDbEntry[]): VulnDbEntry {
  return matches.reduce((worst, candidate) =>
    severityRank(candidate.severity) < severityRank(worst.severity) ? candidate : worst,
  );
}

interface Candidate {
  name: string;
  version: string;
  /** How the version was obtained, for the message. */
  how: string;
  detail: string;
}

/**
 * The versions to check for one skill (PROPOSED_FIXES.md 3.5): every
 * package its lockfile resolves, direct and transitive, when there is one;
 * otherwise each declared specifier's first X.Y.Z token as a stand-in,
 * said so in the message, since a range's real resolution may differ.
 */
function candidates(skill: Skill): Candidate[] {
  const deps = skill.dependencies;
  if (deps.resolved !== null && deps.lockfilePath !== null) {
    const lockfile = path.basename(deps.lockfilePath);
    return deps.resolved.map(({ name, version }) => ({
      name,
      version,
      how: `${name}@${version}, ${name in deps.versionsByName ? 'a direct' : 'a transitive'} dependency resolved by ${lockfile}`,
      detail: `${name}@${version}`,
    }));
  }
  return Object.entries(deps.versionsByName).flatMap(([name, specifier]) => {
    const base = extractBaseVersion(specifier);
    return base === null
      ? []
      : [
          {
            name,
            version: base,
            how: `${name}@${specifier} (no lockfile, so matched as ${base}; the installed version may differ)`,
            detail: `${name}@${specifier}`,
          },
        ];
  });
}

export const chapSup003KnownVulnerableDependencies: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'supply-chain',
  owasp: OWASP,
  detects:
    'A skill dependency, direct or transitive, whose version matches a known vulnerability in a bundled, offline OSV snapshot (or an OSV export passed with `--vuln-db`).',
  heuristic:
    'When the skill has a `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, or `pnpm-lock.yaml`, every resolved package version in it, direct and transitive, is matched exactly. Without a lockfile, each `package.json` specifier\'s first X.Y.Z token stands in for the version, and the message says so; a specifier with no such token (`"latest"`, `"*"`, a git URL) is skipped. The bundled snapshot (`shared/vulnDb.ts`) covers about 80 packages agent skills commonly use and is refreshed out-of-band with `npm run refresh:vulndb`, never during a scan. Its date is shown in the report header. npm dependencies only.',
  remediation:
    'Upgrade the dependency to a patched version (or remove it if unused). Run `npm audit` for a live check beyond the offline snapshot, or pass a full OSV export with `--vuln-db`.',
  run(model) {
    const db = activeVulnDb();
    const findings: Finding[] = [];
    for (const skill of model.skills) {
      // The advisory data is npm-only (PROPOSED_FIXES.md 3.4).
      if (skill.dependencies.ecosystem !== 'npm') {
        continue;
      }
      for (const candidate of candidates(skill)) {
        const base = extractBaseVersion(candidate.version);
        if (base === null) {
          continue;
        }
        const matches = db.filter(
          (entry) =>
            entry.packageName === candidate.name &&
            isVersionInRange(base, entry.introduced, entry.fixed),
        );
        if (matches.length === 0) {
          continue;
        }
        const worst = worstMatch(matches);
        const ids = [...new Set(matches.map((m) => m.id))];
        const severity: Severity = worst.severity;
        findings.push({
          checkId: ID,
          title: TITLE,
          severity,
          category: 'supply-chain',
          owasp: OWASP,
          message: `Skill '${skill.name}' depends on ${candidate.how}, which has ${String(ids.length)} known ${ids.length === 1 ? 'vulnerability' : 'vulnerabilities'} (${ids.join(', ')}). Most severe: "${worst.summary}" (${worst.severity}), fixed in ${worst.fixed}.`,
          location: {
            filePath:
              skill.dependencies.lockfilePath ?? skill.dependencies.manifestPath ?? skill.dir,
            line: null,
            detail: candidate.detail,
          },
          remediation: `Upgrade ${candidate.name} to ${worst.fixed} or later.`,
        });
      }
    }
    return findings;
  },
};
