import { errorMessage } from '../discovery/errors.js';
import type { DiscoveryProfile } from '../discovery/index.js';
import { FindingSchema, type AgentModel, type Finding } from '../model/types.js';
import type { Check } from './types.js';

export interface RunChecksOptions {
  only?: readonly string[];
  skip?: readonly string[];
  /** When set, checks whose `appliesToProfiles` excludes it are not run. Omitted (plugin/test callers): every check runs. */
  profile?: DiscoveryProfile;
}

export interface RunChecksResult {
  findings: Finding[];
  checksRun: string[];
  checksSkipped: string[];
  /** Checks not run because they don't apply to `options.profile` — distinct from user-requested --only/--skip exclusions. */
  checksNotApplicable: string[];
  internalErrors: Array<{ checkId: string; message: string }>;
}

/**
 * Runs every registered check against the model, applying --only/--skip
 * filters and isolating each check's failures so one broken check can't
 * crash the whole scan.
 */
export function runChecks(
  model: AgentModel,
  checks: readonly Check[],
  options: RunChecksOptions = {},
): RunChecksResult {
  const only = options.only !== undefined ? new Set(options.only) : null;
  const skip = options.skip !== undefined ? new Set(options.skip) : null;

  const findings: Finding[] = [];
  const checksRun: string[] = [];
  const checksSkipped: string[] = [];
  const checksNotApplicable: string[] = [];
  const internalErrors: Array<{ checkId: string; message: string }> = [];
  // Every check, built-in or plugin, sees the same read-only copy: one
  // check can't change what another sees (PROPOSED_FIXES.md 4.4).
  const frozenModel = deepFreeze(structuredClone(model));

  for (const check of checks) {
    if ((only !== null && !only.has(check.id)) || (skip !== null && skip.has(check.id))) {
      checksSkipped.push(check.id);
      continue;
    }
    if (
      options.profile !== undefined &&
      check.appliesToProfiles !== undefined &&
      !check.appliesToProfiles.includes(options.profile)
    ) {
      checksNotApplicable.push(check.id);
      continue;
    }

    try {
      const produced: unknown = check.run(frozenModel);
      findings.push(...validateFindings(check, produced));
      checksRun.push(check.id);
    } catch (err) {
      const message = errorMessage(err);
      internalErrors.push({ checkId: check.id, message });
      findings.push({
        checkId: check.id,
        title: `Internal error running ${check.id}`,
        severity: 'info',
        category: check.category,
        owasp: check.owasp,
        message: `This check failed to run and was skipped: ${message}`,
        location: { filePath: null, line: null, detail: null },
        remediation:
          'This is a bug in Chaperone itself; please report it with the scan target (sanitized) that triggered it.',
      });
    }
  }

  return { findings, checksRun, checksSkipped, checksNotApplicable, internalErrors };
}

/**
 * A check's output must be an array of schema-valid findings carrying the
 * check's own ID (PROPOSED_FIXES.md 4.4). A malformed finding could crash
 * a reporter, and a plugin reporting under another check's ID could
 * impersonate a built-in check. A violation is thrown, so it becomes the
 * same "internal error" finding as a check that throws.
 */
function validateFindings(check: Check, produced: unknown): Finding[] {
  if (!Array.isArray(produced)) {
    throw new Error('run() must return an array of findings');
  }
  return produced.map((candidate, index) => {
    const parsed = FindingSchema.safeParse(candidate);
    if (!parsed.success) {
      throw new Error(
        `finding ${String(index)} is malformed: ${parsed.error.issues
          .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
          .join('; ')}`,
      );
    }
    if (parsed.data.checkId !== check.id) {
      throw new Error(
        `finding ${String(index)} has checkId '${parsed.data.checkId}', but a check may only report its own ID ('${check.id}')`,
      );
    }
    return parsed.data;
  });
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
  }
  return value;
}
