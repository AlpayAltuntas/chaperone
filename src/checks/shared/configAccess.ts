import type { AgentModel, JsonValue } from '../../model/types.js';
import { findConfigKey, getConfigField, isRecord } from '../../discovery/jsonUtils.js';

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

/** `field` is the snake_case key name; camelCase/kebab-case spellings are accepted too (see getConfigField). */
export function getTrustBoolean(configData: JsonValue | null, field: string): boolean | null {
  const trust = getTrust(configData);
  const value = trust === null ? undefined : getConfigField(trust, field);
  return typeof value === 'boolean' ? value : null;
}

export function getTrustToolAllowlist(configData: JsonValue | null): string[] | null {
  const trust = getTrust(configData);
  if (trust === null) {
    return null;
  }
  const value = getConfigField(trust, 'tool_allowlist');
  return Array.isArray(value) && value.every((v) => typeof v === 'string') ? value : null;
}

// Feeds CHAP-INJ-005 (improvement_plan.md 2.9): a per-channel trust-level
// distinction `channels.*.tool_allowlist` doesn't check for — a public
// Discord server and a private, admin-only Telegram chat currently look
// identical to CHAP-INJ-003 once *any* global allowlist exists. Both
// `channels.<name>.public` and `channels.<name>.tool_allowlist` are an
// invented-but-documented convention (same caveat as CHAP-AGY-003/004),
// no real manifest schema exists for these example agents.
export interface EnabledChannel {
  name: string;
  // Missing `public` defaults to true (untrusted) — the same
  // conservative-default posture CHAP-INJ-001 already takes for
  // `mark_untrusted_input`: an unmarked channel is assumed public until
  // proven otherwise, not the other way around.
  public: boolean;
  toolAllowlist: string[] | null;
}

export function getEnabledChannels(configData: JsonValue | null): EnabledChannel[] {
  const channels = isRecord(configData) ? configData['channels'] : undefined;
  if (!isRecord(channels)) {
    return [];
  }
  const result: EnabledChannel[] = [];
  for (const [name, value] of Object.entries(channels)) {
    if (!isRecord(value) || value['enabled'] !== true) {
      continue;
    }
    const publicField = value['public'];
    const allowlist = getConfigField(value, 'tool_allowlist');
    result.push({
      name,
      public: typeof publicField === 'boolean' ? publicField : true,
      toolAllowlist:
        Array.isArray(allowlist) && allowlist.every((v) => typeof v === 'string')
          ? allowlist
          : null,
    });
  }
  return result;
}

/**
 * The source line of a config key, given its snake_case path
 * (`['trust', 'auto_execute_links']`), in whatever spelling the config
 * uses. When the full path doesn't exist, returns the line of its deepest
 * existing ancestor (the `trust:` section a missing key belongs in), or
 * null when not even the first key exists (PROPOSED_FIXES.md 4.2).
 */
export function configLine(model: AgentModel, keyPath: readonly string[]): number | null {
  let node: unknown = model.config.data;
  const actual: string[] = [];
  let line: number | null = null;
  for (const segment of keyPath) {
    if (!isRecord(node)) {
      break;
    }
    const key = findConfigKey(node, segment);
    if (key === undefined) {
      break;
    }
    actual.push(key);
    line = model.config.keyLines[actual.join('.')] ?? line;
    node = node[key];
  }
  return line;
}
