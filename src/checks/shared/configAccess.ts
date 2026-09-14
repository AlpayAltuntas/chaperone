import type { JsonValue } from '../../model/types.js';
import { isRecord } from '../../discovery/jsonUtils.js';

/**
 * Reads the `trust`/`channels` sections that CHAP-INJ-* checks need
 * straight out of `model.config.data`. Section 8's six AgentModel buckets
 * don't include a dedicated "trust"/"channels" concept — per DECISIONS.md
 * (Phase 1), that's deliberate: neither field is secret-shaped, so both
 * survive discovery's masking pass untouched, and reading them here is
 * pure data traversal over an already-parsed in-memory tree, not I/O.
 */

export function isAnyChannelEnabled(configData: JsonValue | null): boolean {
  const channels = isRecord(configData) ? configData['channels'] : undefined;
  if (!isRecord(channels)) {
    return false;
  }
  return Object.values(channels).some(
    (channel) => isRecord(channel) && channel['enabled'] === true,
  );
}

function getTrust(configData: JsonValue | null): Record<string, unknown> | null {
  const trust = isRecord(configData) ? configData['trust'] : undefined;
  return isRecord(trust) ? trust : null;
}

export function getTrustBoolean(configData: JsonValue | null, field: string): boolean | null {
  const trust = getTrust(configData);
  if (trust === null || typeof trust[field] !== 'boolean') {
    return null;
  }
  return trust[field];
}

export function getTrustToolAllowlist(configData: JsonValue | null): string[] | null {
  const trust = getTrust(configData);
  if (trust === null) {
    return null;
  }
  const value = trust['tool_allowlist'];
  return Array.isArray(value) && value.every((v) => typeof v === 'string') ? value : null;
}
