import type { GatewayModel } from '../model/types.js';
import { looksLikeEnvReference, looksLikeSecretKeyName } from './configParser.js';
import { isRecord } from './jsonUtils.js';

// Values commonly used as stand-ins for "no real credential configured".
const WEAK_TOKENS = new Set(['', 'changeme', 'change-me', 'default', 'password', 'admin', 'token']);

const EMPTY_GATEWAY: GatewayModel = {
  present: false,
  bindHost: null,
  port: null,
  authConfigured: null,
  authTokenIsDefaultOrEmpty: null,
  authTokenWeakness: null,
  tlsEnabled: null,
};

// A random token shorter than this is brute-forceable against an API
// that doesn't rate-limit (PROPOSED_FIXES.md 3.8).
const MIN_TOKEN_LENGTH = 16;

/** Every literal string under a secret-shaped key, except at the gateway credential paths. */
function otherSecretValues(node: unknown, skipPaths: readonly string[], prefix = ''): string[] {
  if (Array.isArray(node)) {
    return node.flatMap((item, i) => otherSecretValues(item, skipPaths, `${prefix}[${String(i)}]`));
  }
  if (!isRecord(node)) {
    return [];
  }
  return Object.entries(node).flatMap(([key, value]) => {
    const keyPath = prefix ? `${prefix}.${key}` : key;
    if (skipPaths.includes(keyPath)) {
      return [];
    }
    if (typeof value === 'string') {
      return looksLikeSecretKeyName(key) && !looksLikeEnvReference(value) && value !== ''
        ? [value]
        : [];
    }
    return otherSecretValues(value, skipPaths, keyPath);
  });
}

function tokenWeakness(
  token: string | null,
  rawConfig: Record<string, unknown>,
): GatewayModel['authTokenWeakness'] {
  if (token === null || looksLikeEnvReference(token)) {
    return null;
  }
  const trimmed = token.trim();
  if (trimmed === '') {
    return 'empty';
  }
  if (WEAK_TOKENS.has(trimmed.toLowerCase())) {
    return 'default';
  }
  if (
    otherSecretValues(rawConfig, ['gateway.auth.token', 'gateway.auth.password']).includes(token)
  ) {
    return 'reused';
  }
  return trimmed.length < MIN_TOKEN_LENGTH ? 'short' : null;
}

/**
 * OpenClaw's `gateway.bind` mode as a host (PROPOSED_FIXES.md 6.2, keys
 * checked against docs.openclaw.ai on 2026-10-04): `loopback` is
 * 127.0.0.1, `lan` is 0.0.0.0, `custom` is `customBindHost`. `tailnet`
 * and `auto` depend on the machine, so they're unknown (null), which
 * CHAP-NET-001 reports as "verify the default" rather than guessing.
 */
function bindModeHost(gateway: Record<string, unknown>): string | null {
  switch (gateway['bind']) {
    case 'loopback':
      return '127.0.0.1';
    case 'lan':
      return '0.0.0.0';
    case 'custom':
      return typeof gateway['customBindHost'] === 'string' ? gateway['customBindHost'] : null;
    default:
      return null;
  }
}

/**
 * Projects gateway/network facts out of the RAW (pre-mask) parsed config.
 * Must run before configParser's masking pass — an empty/default auth token
 * is exactly the kind of literal value masking would otherwise obscure. Only
 * derived booleans are kept; the raw token string itself is never stored in
 * the model.
 */
export function extractGatewayModel(rawConfig: unknown): GatewayModel {
  if (!isRecord(rawConfig)) {
    return EMPTY_GATEWAY;
  }
  const gateway = rawConfig['gateway'];
  if (!isRecord(gateway)) {
    return EMPTY_GATEWAY;
  }

  const bindHost = typeof gateway['host'] === 'string' ? gateway['host'] : bindModeHost(gateway);
  const port = typeof gateway['port'] === 'number' ? gateway['port'] : null;

  const auth = gateway['auth'];
  // OpenClaw's `auth.mode: "none"` is auth explicitly turned off; its
  // `password` mode uses `auth.password` as the shared secret
  // (PROPOSED_FIXES.md 6.2).
  const authConfigured = isRecord(auth) && auth['mode'] !== 'none';
  const token =
    isRecord(auth) && typeof auth['token'] === 'string'
      ? auth['token']
      : isRecord(auth) && auth['mode'] === 'password' && typeof auth['password'] === 'string'
        ? auth['password']
        : null;
  const authTokenIsDefaultOrEmpty =
    token === null ? null : WEAK_TOKENS.has(token.trim().toLowerCase());

  const tls = gateway['tls'];
  const tlsEnabled =
    typeof tls === 'boolean'
      ? tls
      : isRecord(tls) && typeof tls['enabled'] === 'boolean'
        ? tls['enabled']
        : null;

  const authTokenWeakness = tokenWeakness(token, rawConfig);
  return {
    present: true,
    bindHost,
    port,
    authConfigured,
    authTokenIsDefaultOrEmpty,
    authTokenWeakness,
    tlsEnabled,
  };
}
