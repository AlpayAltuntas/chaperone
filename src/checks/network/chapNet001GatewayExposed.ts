import { BlockList, isIP } from 'node:net';
import type { Check } from '../../engine/types.js';
import { configLine } from '../shared/configAccess.js';

const ID = 'CHAP-NET-001';
const TITLE = 'Gateway bound beyond localhost';
const OWASP = 'LLM06 / general';

/**
 * Whether `host` is a loopback address — i.e. genuinely reachable only
 * from the same machine, not merely equal to the one canonical spelling
 * of localhost. Covers the IPv4 127.0.0.0/8 block, the IPv6 loopback in
 * any spelling (`::1`, `0:0:0:0:0:0:0:1`), and IPv4-mapped loopback
 * (`::ffff:127.0.0.1`), after normalizing the forms people actually write
 * in a `host` field: a trailing `:port`, `[...]` brackets around IPv6,
 * and a trailing-dot `localhost.`. Each of those used to be a critical
 * false positive (PROPOSED_FIXES.md 2.2).
 */
export function isLoopbackAddress(host: string): boolean {
  const address = stripPortAndBrackets(host.trim()).toLowerCase();
  if (address === 'localhost' || address === 'localhost.') {
    return true;
  }

  const family = isIP(address);
  if (family === 4) {
    return LOOPBACK.check(address, 'ipv4');
  }
  if (family === 6) {
    const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(address);
    if (mapped?.[1] !== undefined) {
      return isIP(mapped[1]) === 4 && LOOPBACK.check(mapped[1], 'ipv4');
    }
    return LOOPBACK.check(address, 'ipv6');
  }
  return false;
}

const LOOPBACK = new BlockList();
LOOPBACK.addSubnet('127.0.0.0', 8, 'ipv4');
LOOPBACK.addAddress('::1', 'ipv6');

/**
 * `[::1]:8080` -> `::1`, `[::1]` -> `::1`, `127.0.0.1:8080` -> `127.0.0.1`,
 * `localhost:80` -> `localhost`. A bare IPv6 address (two or more colons,
 * no brackets) is returned unchanged — its last group can't be told apart
 * from a port, which is exactly why IPv6-with-port must be bracketed.
 */
function stripPortAndBrackets(host: string): string {
  const bracketed = /^\[([^\]]*)\](?::\d+)?$/.exec(host);
  if (bracketed?.[1] !== undefined) {
    return bracketed[1];
  }
  const singleColon = /^([^:]+):\d+$/.exec(host);
  if (singleColon?.[1] !== undefined) {
    return singleColon[1];
  }
  return host;
}

export const chapNet001GatewayExposed: Check = {
  id: ID,
  title: TITLE,
  severity: 'critical',
  category: 'network',
  owasp: OWASP,
  detects:
    'The gateway daemon listening on an interface other than localhost (e.g. `0.0.0.0`), making it reachable from other hosts.',
  heuristic:
    '`gateway.host` in config is present and is not a loopback address (`localhost`, anything in `127.0.0.0/8`, `::1`, or IPv4-mapped `::ffff:127.x.x.x`). A trailing `:port` and `[...]` IPv6 brackets are stripped before classifying.',
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
        location: {
          filePath: model.config.path,
          line: configLine(model, ['gateway', 'host']),
          detail: 'gateway.host',
        },
        remediation:
          'Bind the gateway to 127.0.0.1/localhost; put anything that must be remote behind a tunnel with authentication.',
      },
    ];
  },
};
