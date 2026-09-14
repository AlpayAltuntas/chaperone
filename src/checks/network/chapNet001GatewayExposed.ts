import type { Check } from '../../engine/types.js';

const ID = 'CHAP-NET-001';
const TITLE = 'Gateway bound beyond localhost';
const OWASP = 'LLM06 / general';

const LOCALHOST_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

/** Flags a gateway bind address that isn't localhost, making it reachable from other hosts. */
export const chapNet001GatewayExposed: Check = {
  id: ID,
  title: TITLE,
  severity: 'critical',
  category: 'network',
  owasp: OWASP,
  run(model) {
    const { gateway } = model;
    if (!gateway.present || gateway.bindHost === null || LOCALHOST_HOSTS.has(gateway.bindHost)) {
      return [];
    }

    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'critical',
        category: 'network',
        owasp: OWASP,
        message: `The gateway is bound to '${gateway.bindHost}', not localhost, making it reachable from other hosts on the network.`,
        location: { filePath: model.config.path, line: null, detail: 'gateway.host' },
        remediation:
          'Bind the gateway to 127.0.0.1/localhost; put anything that must be remote behind a tunnel with authentication.',
      },
    ];
  },
};
