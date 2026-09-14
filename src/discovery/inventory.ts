import type { AgentModel } from '../model/types.js';

/**
 * Renders a plain-text inventory of what discovery found — a diagnostic view
 * for Phase 1, before the check engine and real reporters exist. Findings,
 * severities, and a posture score are produced by the engine/reporters in
 * later phases; this only ever describes what was inspected.
 */
export function formatInventorySummary(model: AgentModel, targetRootResolved: boolean): string[] {
  const lines: string[] = [];

  lines.push('Chaperone — discovery inventory');
  lines.push(`Target root: ${model.targetRoot}${targetRootResolved ? '' : ' (not found)'}`);

  if (model.config.path !== null) {
    lines.push(`Config: ${model.config.path} (${model.config.format ?? 'unknown format'})`);
    const literalSecrets = model.config.secretFields.filter((f) => !f.looksLikeEnvReference);
    const envRefSecrets = model.config.secretFields.filter((f) => f.looksLikeEnvReference);
    lines.push(
      `  secret-like fields: ${model.config.secretFields.length} total, ` +
        `${literalSecrets.length} literal (masked), ${envRefSecrets.length} via env reference`,
    );
    for (const field of literalSecrets) {
      lines.push(`    - ${field.keyPath}: ${field.displayValue}`);
    }
  } else {
    lines.push('Config: not found');
  }

  lines.push(
    `Gateway: present=${model.gateway.present} bind=${model.gateway.bindHost ?? 'unknown'}:${model.gateway.port ?? 'unknown'} ` +
      `authConfigured=${fmtBool(model.gateway.authConfigured)} authTokenWeak=${fmtBool(model.gateway.authTokenIsDefaultOrEmpty)} ` +
      `tls=${fmtBool(model.gateway.tlsEnabled)}`,
  );

  lines.push(
    `Logging: present=${model.logging.present} level=${model.logging.level ?? 'unknown'} path=${model.logging.path ?? 'unknown'} ` +
      `redactSecrets=${fmtBool(model.logging.redactSecrets)} auditLog=${fmtBool(model.logging.auditLogEnabled)}`,
  );

  lines.push(
    `Git context: ancestorGitDir=${model.git.hasAncestorGitDir}` +
      (model.git.hasAncestorGitDir
        ? ` root=${model.git.gitRootPath ?? 'unknown'} gitignorePatterns=${model.git.gitignorePatterns.length}`
        : ''),
  );

  lines.push(`Skills discovered: ${model.skills.length}`);
  for (const skill of model.skills) {
    lines.push(
      `  - ${skill.name}: shellExec=${skill.capabilities.shellExec} fsAccess=${skill.capabilities.fileSystemAccess} ` +
        `network=${skill.capabilities.networkAccess} destructive=[${skill.capabilities.destructiveKeywords.join(', ')}] ` +
        `pinnedRef=${fmtBool(skill.provenance.pinnedRef)} lockfile=${skill.dependencies.lockfilePath !== null}`,
    );
    for (const script of skill.installScripts.scripts) {
      lines.push(
        `      dangerous install pattern in ${script.path}: ${script.dangerousPatterns.join(', ')}`,
      );
    }
  }

  lines.push(`Permissions checked: ${model.permissions.length}`);
  for (const fact of model.permissions) {
    lines.push(
      `  - ${fact.path}: mode=${fact.mode !== null ? fact.mode.toString(8) : 'unknown'} ` +
        `groupOrOtherReadable=${fmtBool(fact.groupOrOtherReadable)}`,
    );
  }

  lines.push(`Inspected: ${model.inspected.length} paths`);
  lines.push(`Skipped: ${model.skipped.length} paths`);
  for (const entry of model.skipped) {
    lines.push(`  - ${entry.path}: ${entry.reason}`);
  }

  return lines;
}

function fmtBool(value: boolean | null): string {
  return value === null ? 'unknown' : String(value);
}
