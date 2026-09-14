import type { GatewayModel } from '../model/types.js';
import { isRecord } from './jsonUtils.js';

// Values commonly used as stand-ins for "no real credential configured".
const WEAK_TOKENS = new Set(['', 'changeme', 'change-me', 'default', 'password', 'admin', 'token']);

const EMPTY_GATEWAY: GatewayModel = {
  present: false,
  bindHost: null,
  port: null,
  authConfigured: null,
  authTokenIsDefaultOrEmpty: null,
  tlsEnabled: null,
};

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

  const bindHost = typeof gateway['host'] === 'string' ? gateway['host'] : null;
  const port = typeof gateway['port'] === 'number' ? gateway['port'] : null;

  const auth = gateway['auth'];
  const authConfigured = isRecord(auth);
  const token = isRecord(auth) && typeof auth['token'] === 'string' ? auth['token'] : null;
  const authTokenIsDefaultOrEmpty =
    token === null ? null : WEAK_TOKENS.has(token.trim().toLowerCase());

  const tls = gateway['tls'];
  const tlsEnabled =
    typeof tls === 'boolean'
      ? tls
      : isRecord(tls) && typeof tls['enabled'] === 'boolean'
        ? tls['enabled']
        : null;

  return { present: true, bindHost, port, authConfigured, authTokenIsDefaultOrEmpty, tlsEnabled };
}
