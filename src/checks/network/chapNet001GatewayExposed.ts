import type { Check } from '../../engine/types.js';

const ID = 'CHAP-NET-001';
const TITLE = 'Gateway bound beyond localhost';
const OWASP = 'LLM06 / general';

/**
 * Whether `host` is a loopback address — i.e. genuinely reachable only
 * from the same machine, not merely equal to the one canonical spelling
 * of localhost. Previously this only recognized the exact literals
 * '127.0.0.1'/'localhost'/'::1', which false-positived on any other
 * address in the (entirely loopback) IPv4 127.0.0.0/8 block, e.g.
 * '127.0.0.2', and on the IPv6 loopback written in expanded form, e.g.
 * '0:0:0:0:0:0:0:1' (see improvement_plan.md 1.3). Not a full RFC-grade
 * IPv6 parser — e.g. IPv4-mapped IPv6 loopback ('::ffff:127.0.0.1') isn't
 * recognized — but covers the realistic config-value cases.
 */
export function isLoopbackAddress(host: string): boolean {
  const normalized = host.trim();
  if (normalized.toLowerCase() === 'localhost') {
    return true;
  }

  const ipv4Match = /^(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.exec(normalized);
  if (ipv4Match) {
    return Number(ipv4Match[1]) === 127;
  }

  if (normalized.includes(':')) {
    const nonEmptyGroups = normalized.split(':').filter((group) => group.length > 0);
    if (nonEmptyGroups.length === 0) {
      return false; // '::' — the IPv6 "any address" wildcard, not loopback.
    }
    const last = nonEmptyGroups[nonEmptyGroups.length - 1] ?? '';
    const rest = nonEmptyGroups.slice(0, -1);
    return /^0*1$/.test(last) && rest.every((group) => /^0+$/.test(group));
  }

  return false;
}

/** Flags a gateway bind address that isn't localhost, making it reachable from other hosts. */
export const chapNet001GatewayExposed: Check = {
  id: ID,
  title: TITLE,
  severity: 'critical',
  category: 'network',
  owasp: OWASP,
  detects:
    'The gateway daemon listening on an interface other than localhost (e.g. `0.0.0.0`), making it reachable from other hosts.',
  heuristic: '`gateway.host` in config is present and is not `127.0.0.1`, `localhost`, or `::1`.',
  remediation:
    'Bind the gateway to `127.0.0.1`/`localhost`; put anything that must be reachable remotely behind a tunnel with authentication.',
  run(model) {
    const { gateway } = model;
    if (!gateway.present || gateway.bindHost === null || isLoopbackAddress(gateway.bindHost)) {
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
