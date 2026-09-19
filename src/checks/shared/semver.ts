/**
 * Minimal semver-adjacent helpers for CHAP-SUP-003's offline
 * vulnerability match (improvement_plan.md 1.15/Phase 18) — deliberately
 * not a general-purpose semver range intersection engine (no `semver`
 * dependency; this project keeps a small dependency footprint, same
 * spirit as `levenshtein.ts` being hand-rolled rather than pulled in).
 *
 * This is a static, config-only scan: there is no lockfile parsing and
 * no node_modules inspection, so the *actual resolved* version a real
 * install would use is never available — only the raw specifier string
 * written in package.json (`"^4.17.15"`, `"~1.2.5"`, `"4.17.15"`, ...).
 * `extractBaseVersion` takes the first X.Y.Z-shaped token in that
 * specifier as a stand-in for "the version this dependency most plausibly
 * resolves to" — a real limitation (a caret range's actual resolution
 * could land on a patched version even when its declared floor looks
 * vulnerable, or float higher into a *newly*-vulnerable one), but a much
 * stronger, more honest signal than CHAP-SUP-003's previous "fires on any
 * manifest, always" behavior. Documented, not silent — see DECISIONS.md,
 * Phase 18.
 */
export function extractBaseVersion(specifier: string): string | null {
  const match = /\d+\.\d+\.\d+/.exec(specifier);
  return match ? match[0] : null;
}

/** Compares two X.Y.Z version strings numerically, part by part (not lexicographically — "4.9.0" < "4.17.0"). Returns <0, 0, or >0. */
export function compareVersions(a: string, b: string): number {
  const partsA = a.split('.').map(Number);
  const partsB = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (partsA[i] ?? 0) - (partsB[i] ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }
  return 0;
}

/** True when `version` falls in the vulnerable range `[introduced, fixed)`. */
export function isVersionInRange(version: string, introduced: string, fixed: string): boolean {
  return compareVersions(version, introduced) >= 0 && compareVersions(version, fixed) < 0;
}
