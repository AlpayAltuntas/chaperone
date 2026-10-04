import path from 'node:path';
import type { LoggingModel } from '../model/types.js';
import { getConfigField, isRecord } from './jsonUtils.js';
import { expandHome } from './pathUtils.js';

const EMPTY_LOGGING: LoggingModel = {
  present: false,
  level: null,
  path: null,
  redactSecrets: null,
  auditLogEnabled: null,
  existingSecretMatches: [],
};

/** Projects logging/observability facts out of the raw parsed config, resolving a relative log path against the target root. */
export function extractLoggingModel(rawConfig: unknown, targetRoot: string): LoggingModel {
  if (!isRecord(rawConfig)) {
    return EMPTY_LOGGING;
  }
  const logging = rawConfig['logging'];
  if (!isRecord(logging)) {
    return EMPTY_LOGGING;
  }

  const level = typeof logging['level'] === 'string' ? logging['level'] : null;
  const rawPath = typeof logging['path'] === 'string' ? logging['path'] : null;
  const resolvedPath = rawPath !== null ? path.resolve(targetRoot, expandHome(rawPath)) : null;

  const redact = getConfigField(logging, 'redact_secrets');
  const redactSecrets = typeof redact === 'boolean' ? redact : null;

  const audit = logging['audit'];
  const auditLogEnabled =
    typeof audit === 'boolean'
      ? audit
      : isRecord(audit) && typeof audit['enabled'] === 'boolean'
        ? audit['enabled']
        : null;

  return {
    present: true,
    level,
    path: resolvedPath,
    redactSecrets,
    auditLogEnabled,
    existingSecretMatches: [],
  };
}
