import { errorMessage } from '../discovery/errors.js';
import type { DiscoveryProfile } from '../discovery/index.js';
import type { AgentModel, Finding } from '../model/types.js';
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
      findings.push(...check.run(model));
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
