import { existsSync, readFileSync } from 'node:fs';
import { z } from 'zod';
import { errorMessage } from '../discovery/errors.js';
import { SeveritySchema, type Finding, type Severity } from '../model/types.js';

// Per-project suppression config file (improvement_plan.md 3.4) — an
// explicit §16 stretch goal, since there was previously no way to
// override a check's severity or consciously suppress a specific
// finding. Read-only, local, no different in kind from any other config
// file Chaperone reads — no new guardrail concerns.

export const DEFAULT_CONFIG_FILENAME = '.chaperonerc.json';

const IgnoreEntrySchema = z.object({
  checkId: z.string(),
  reason: z.string().optional(),
  // ISO date string (YYYY-MM-DD). An expired entry stops suppressing —
  // see applyChaperoneConfig — rather than silently outliving its
  // reason forever, the exact problem an `expires` field exists to
  // solve (borrowed from real-world security-linter suppression configs).
  expires: z.string().optional(),
});
export type IgnoreEntry = z.infer<typeof IgnoreEntrySchema>;

export const ChaperoneConfigSchema = z.object({
  severityOverrides: z.record(z.string(), SeveritySchema).optional(),
  ignore: z.array(IgnoreEntrySchema).optional(),
  disabledChecks: z.array(z.string()).optional(),
  scoreWeights: z.partialRecord(SeveritySchema, z.number()).optional(),
});
export type ChaperoneConfig = z.infer<typeof ChaperoneConfigSchema>;

export interface LoadedConfig {
  config: ChaperoneConfig;
  /** The file actually loaded, or null when nothing was found/requested — a missing default file is normal, not an error. */
  path: string | null;
}

/**
 * Loads and validates `.chaperonerc.json`. An explicit `--config <file>`
 * must exist and parse/validate — silently ignoring a typo'd path would
 * be worse than failing loudly, so both are thrown as errors for the
 * caller to turn into a clean `command.error()` (matching how an
 * unknown `--only`/`--skip` check ID is already handled in cli.ts).
 * With no explicit path, `DEFAULT_CONFIG_FILENAME` is looked up in the
 * current working directory; its absence just means no suppressions.
 */
export function loadChaperoneConfig(explicitPath?: string): LoadedConfig {
  const path =
    explicitPath ?? (existsSync(DEFAULT_CONFIG_FILENAME) ? DEFAULT_CONFIG_FILENAME : null);
  if (path === null) {
    return { config: {}, path: null };
  }
  if (!existsSync(path)) {
    throw new Error(`config file not found: ${path}`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`could not parse ${path} as JSON: ${errorMessage(err)}`, { cause: err });
  }

  const result = ChaperoneConfigSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
    throw new Error(`invalid ${path}: ${issues}`);
  }
  return { config: result.data, path };
}

export interface ApplyConfigResult {
  findings: Finding[];
  warnings: string[];
}

/**
 * Applies `severityOverrides` and `ignore` suppressions to an
 * already-run finding set — a real reclassification the user has
 * consciously made, so (unlike the purely cosmetic `--only-category`/
 * `--min-severity` display filters from improvement_plan.md 3.8) this
 * result feeds `--fail-on` and the posture score too, not just display.
 * `disabledChecks` is handled earlier, feeding into `runChecks`'s own
 * `skip` mechanism — those checks never run at all, so there's nothing
 * here to suppress for them.
 */
export function applyChaperoneConfig(
  findings: readonly Finding[],
  config: ChaperoneConfig,
  knownCheckIds: ReadonlySet<string>,
  now: Date = new Date(),
): ApplyConfigResult {
  const warnings: string[] = [];
  const severityOverrides = config.severityOverrides ?? {};

  for (const checkId of Object.keys(severityOverrides)) {
    if (!knownCheckIds.has(checkId)) {
      warnings.push(
        `.chaperonerc.json: severityOverrides references unknown check ID '${checkId}'`,
      );
    }
  }

  const activeIgnoreCheckIds = new Set<string>();
  for (const entry of config.ignore ?? []) {
    if (!knownCheckIds.has(entry.checkId)) {
      warnings.push(
        `.chaperonerc.json: ignore entry references unknown check ID '${entry.checkId}'`,
      );
    }

    if (entry.expires !== undefined) {
      const expiresAt = new Date(entry.expires);
      if (!Number.isNaN(expiresAt.getTime()) && expiresAt.getTime() < now.getTime()) {
        const reasonSuffix = entry.reason !== undefined ? ` (reason: ${entry.reason})` : '';
        warnings.push(
          `suppression for ${entry.checkId} expired on ${entry.expires}${reasonSuffix} — no longer suppressed; re-review and update .chaperonerc.json`,
        );
        continue;
      }
    }
    activeIgnoreCheckIds.add(entry.checkId);
  }

  const resultFindings = findings
    .filter((finding) => !activeIgnoreCheckIds.has(finding.checkId))
    .map((finding): Finding => {
      const overrideSeverity: Severity | undefined = severityOverrides[finding.checkId];
      return overrideSeverity !== undefined ? { ...finding, severity: overrideSeverity } : finding;
    });

  return { findings: resultFindings, warnings };
}
