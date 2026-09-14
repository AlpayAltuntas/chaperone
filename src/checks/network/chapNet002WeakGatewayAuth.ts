import type { Check } from '../../engine/types.js';

const ID = 'CHAP-NET-002';
const TITLE = 'Missing or weak auth on the gateway control API';
const OWASP = 'General';

/** Flags a gateway with no auth configured, or an empty/default-looking auth token. */
export const chapNet002WeakGatewayAuth: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'network',
  owasp: OWASP,
  run(model) {
    const { gateway } = model;
    if (!gateway.present) {
      return [];
    }
    const weak = gateway.authConfigured !== true || gateway.authTokenIsDefaultOrEmpty === true;
    if (!weak) {
      return [];
    }

    const reason =
      gateway.authConfigured !== true
        ? 'no auth is configured at all'
        : 'the auth token is empty or a common default value';
    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'high',
        category: 'network',
        owasp: OWASP,
        message: `The gateway's control API has weak authentication: ${reason}.`,
        location: { filePath: model.config.path, line: null, detail: 'gateway.auth.token' },
        remediation:
          'Require a strong, randomly-generated token for the gateway control API and rotate any default value.',
      },
    ];
  },
};
