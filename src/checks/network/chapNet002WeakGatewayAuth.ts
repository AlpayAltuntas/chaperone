import type { Check } from '../../engine/types.js';
import { configLine } from '../shared/configAccess.js';
import { isLoopbackAddress } from './chapNet001GatewayExposed.js';

const ID = 'CHAP-NET-002';
const TITLE = 'Missing or weak auth on the gateway control API';
const OWASP = 'General';

const REMEDIATION =
  'Require a strong, randomly generated token (at least 16 characters, used nowhere else) for the gateway control API, and rotate any default or reused value.';

const WEAKNESS_REASON = {
  empty: 'the auth token is empty',
  default: 'the auth token is a common default value',
  short: 'the auth token is shorter than 16 characters',
  reused: 'the auth token is the same value as another secret in the config',
} as const;

/**
 * Flags a gateway with no auth configured, or a weak literal token
 * (PROPOSED_FIXES.md 3.8). Downgraded to medium when the gateway is bound
 * to loopback (CHAP-NET-001 clean): still reachable from the local
 * machine and, through browser-to-localhost or DNS-rebinding attacks,
 * from web pages it visits, but not from the network.
 */
export const chapNet002WeakGatewayAuth: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  severityNote: 'High (Medium when the gateway is bound to loopback)',
  category: 'network',
  owasp: OWASP,
  detects: 'The gateway control API with no auth configured, or a weak credential.',
  heuristic:
    "`gateway.auth` is absent, or its literal `token` is empty, a common default (`changeme`, `admin`, `password`, `default`, `token`, case-insensitive), shorter than 16 characters, or identical to another secret value in the config. An env-var reference (`${GW_TOKEN}`) isn't judged. When `gateway.host` is a loopback address, the finding is medium instead of high: there's no network exposure, but local processes and web pages using browser-to-localhost or DNS rebinding can still reach it.",
  remediation: REMEDIATION,
  run(model) {
    const { gateway } = model;
    if (!gateway.present) {
      return [];
    }
    const reason =
      gateway.authConfigured !== true
        ? 'no auth is configured at all'
        : gateway.authTokenWeakness !== null
          ? WEAKNESS_REASON[gateway.authTokenWeakness]
          : gateway.authTokenIsDefaultOrEmpty === true
            ? 'the auth token is empty or a common default value'
            : null;
    if (reason === null) {
      return [];
    }
    const loopback = gateway.bindHost !== null && isLoopbackAddress(gateway.bindHost);
    return [
      {
        checkId: ID,
        title: TITLE,
        severity: loopback ? 'medium' : 'high',
        category: 'network',
        owasp: OWASP,
        message: `The gateway's control API has weak authentication: ${reason}.${loopback ? ' It is bound to loopback, so it is not reachable from the network, but local processes and web pages (via browser-to-localhost or DNS rebinding) can still reach it.' : ''}`,
        location: {
          filePath: model.config.path,
          line: configLine(model, ['gateway', 'auth', 'token']),
          detail: 'gateway.auth.token',
        },
        remediation: REMEDIATION,
      },
    ];
  },
};
