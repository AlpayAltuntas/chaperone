import { severityRank } from '../../engine/severity.js';
import type { Check } from '../../engine/types.js';
import type { Finding, Severity } from '../../model/types.js';
import { extractBaseVersion, isVersionInRange } from '../shared/semver.js';
import { VULN_DB, type VulnDbEntry } from '../shared/vulnDb.js';

const ID = 'CHAP-SUP-003';
const TITLE = 'Known-vulnerable dependency';
const OWASP = 'LLM05: Supply Chain';

/**
 * Real fix (improvement_plan.md 1.15, Phase 18): matches each skill's
 * declared dependency version against a small, bundled, offline
 * vulnerability snapshot (`shared/vulnDb.ts`, refreshed out-of-band via
 * `npm run refresh:vulndb` — see `scripts/refreshVulnDb.ts` — never
 * fetched live during a scan). Severity restored to the category's
 * normal weight now that the signal is a genuine version match, not
 * "any manifest exists" (this check's previous, deliberately weak, v1
 * behavior — see DECISIONS.md, Phase 18, for the full before/after).
 *
 * `extractBaseVersion`/`isVersionInRange` (semver.ts) are a deliberately
 * simple, static, config-only match: no lockfile parsing, no
 * node_modules inspection, so the actual *resolved* version a real
 * install would use is never available — only the first X.Y.Z token in
 * the raw package.json specifier stands in for it. A specifier with no
 * such token (`"latest"`, `"*"`, a git URL, a workspace reference) can't
 * be evaluated and is silently skipped — conservative by design, never
 * guessed at.
 */
function worstMatch(matches: readonly VulnDbEntry[]): VulnDbEntry {
  return matches.reduce((worst, candidate) =>
    severityRank(candidate.severity) < severityRank(worst.severity) ? candidate : worst,
  );
}

export const chapSup003KnownVulnerableDependencies: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'supply-chain',
  owasp: OWASP,
  detects:
    'A skill dependency whose declared version matches a known vulnerability in a small, bundled, offline snapshot (OSV.dev-sourced).',
  heuristic:
    'Compares each skill\'s package.json dependency version specifiers against `shared/vulnDb.ts`, a curated, offline snapshot of real advisories for a small set of well-known npm packages, refreshed out-of-band via `npm run refresh:vulndb` (never during a scan — see `scripts/refreshVulnDb.ts`). A specifier\'s first X.Y.Z-shaped token stands in for the version, since no lockfile/node_modules resolution is available in a static config-only scan; a specifier with no such token (`"latest"`, `"*"`, a git URL) is skipped rather than guessed at. Not exhaustive — only tracks the packages in the bundled snapshot, not the full OSV/npm-advisory database.',
  remediation:
    'Upgrade the dependency to a patched version (or remove it if unused). Run `npm audit` for a live, comprehensive check beyond this offline snapshot.',
  run(model) {
    const findings: Finding[] = [];
    for (const skill of model.skills) {
      for (const [depName, specifier] of Object.entries(skill.dependencies.versionsByName)) {
        const baseVersion = extractBaseVersion(specifier);
        if (baseVersion === null) {
          continue;
        }
        const matches = VULN_DB.filter(
          (entry) =>
            entry.packageName === depName &&
            isVersionInRange(baseVersion, entry.introduced, entry.fixed),
        );
        if (matches.length === 0) {
          continue;
        }
        const worst = worstMatch(matches);
        const idList = matches.map((m) => m.id).join(', ');
        const severity: Severity = worst.severity;
        findings.push({
          checkId: ID,
          title: TITLE,
          severity,
          category: 'supply-chain',
          owasp: OWASP,
          message: `Skill '${skill.name}' depends on ${depName}@${specifier} (matched as ${baseVersion}), which hits ${String(matches.length)} known ${matches.length === 1 ? 'vulnerability' : 'vulnerabilities'} in Chaperone's offline snapshot (${idList}) — most severe: "${worst.summary}" (${worst.severity}), fixed in ${worst.fixed}.`,
          location: {
            filePath: skill.dependencies.manifestPath ?? skill.manifestPath ?? skill.dir,
            line: null,
            detail: `${depName}@${specifier}`,
          },
          remediation: `Upgrade ${depName} to ${worst.fixed} or later.`,
        });
      }
    }
    return findings;
  },
};
