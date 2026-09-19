import type { Check } from '../../engine/types.js';
import { levenshteinDistance } from '../shared/levenshtein.js';
import { POPULAR_PACKAGE_NAMES } from '../shared/popularPackages.js';

const ID = 'CHAP-SUP-006';
const TITLE = 'Typosquat-risk dependency name';
const OWASP = 'LLM05: Supply Chain';

// A real dependency name is compared against the popular-package list;
// distance 0 (an exact match) is the legitimate case and never flagged.
// Both length floors avoid noise from very short names, where a small
// edit distance is common and meaningless (e.g. "ws" vs "js").
const MAX_TYPOSQUAT_DISTANCE = 2;
const MIN_NAME_LENGTH = 4;

/** Finds the closest well-known package name within MAX_TYPOSQUAT_DISTANCE, or null if `name` is itself well-known or has no close match. */
function findTyposquatMatch(name: string): string | null {
  if (name.length < MIN_NAME_LENGTH || POPULAR_PACKAGE_NAMES.includes(name)) {
    return null;
  }

  let closest: { candidate: string; distance: number } | null = null;
  for (const candidate of POPULAR_PACKAGE_NAMES) {
    if (candidate.length < MIN_NAME_LENGTH) {
      continue;
    }
    const distance = levenshteinDistance(name, candidate);
    if (
      distance > 0 &&
      distance <= MAX_TYPOSQUAT_DISTANCE &&
      (closest === null || distance < closest.distance)
    ) {
      closest = { candidate, distance };
    }
  }
  return closest?.candidate ?? null;
}

/**
 * Flags a skill dependency whose name is suspiciously close (small edit
 * distance) to a well-known popular package — a small bundled reference
 * list is enough for a useful first cut, no live registry lookup needed
 * (preserves the no-network guardrail, improvement_plan.md 2.7).
 */
export const chapSup006TyposquatRisk: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'supply-chain',
  owasp: OWASP,
  detects:
    "A skill dependency whose name is suspiciously close (small edit distance) to a well-known popular package name (e.g. 'reqeust' vs 'request') — a common typosquatting technique.",
  heuristic:
    "The dependency name isn't itself a well-known package, is at least 4 characters, and has a Levenshtein (edit) distance of 1-2 from a well-known package name in a small bundled reference list (no live registry lookup — Chaperone makes no outbound network calls). Not exhaustive: a name not close to anything on that list is never flagged.",
  remediation:
    'Double check the exact spelling against the real package on the registry before installing, and remove the dependency if it was added by mistake.',
  run(model) {
    const findings = [];
    for (const skill of model.skills) {
      for (const dependencyName of skill.dependencies.names) {
        const match = findTyposquatMatch(dependencyName);
        if (match === null) {
          continue;
        }
        findings.push({
          checkId: ID,
          title: TITLE,
          severity: 'medium' as const,
          category: 'supply-chain' as const,
          owasp: OWASP,
          message: `Skill '${skill.name}' depends on '${dependencyName}', which is suspiciously close to the well-known package '${match}' — possible typosquat.`,
          location: {
            filePath: skill.dependencies.manifestPath ?? skill.manifestPath ?? skill.dir,
            line: null,
            detail: dependencyName,
          },
          remediation: `Double check that '${dependencyName}' is the package you actually intend to use, not a typosquat of '${match}'.`,
        });
      }
    }
    return findings;
  },
};
