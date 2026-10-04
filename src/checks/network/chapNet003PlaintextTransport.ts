import type { Check } from '../../engine/types.js';
import type { Finding } from '../../model/types.js';
import { isLoopbackAddress } from './chapNet001GatewayExposed.js';
import { configLine } from '../shared/configAccess.js';

const ID = 'CHAP-NET-003';
const TITLE = 'Plaintext transport on the gateway';
const OWASP = 'General';

/**
 * Flags a gateway that explicitly disables TLS (silent when TLS isn't
 * mentioned at all), and a remote MCP server reached over plaintext
 * `http://` on a non-loopback host (PROPOSED_FIXES.md 3.9).
 */
export const chapNet003PlaintextTransport: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'network',
  owasp: OWASP,
  detects:
    'The gateway explicitly configured without TLS, or a remote MCP server configured with a plaintext `http://` URL.',
  heuristic:
    "`gateway.tls` is explicitly `false` (silent when TLS isn't mentioned in config at all: there's no confident signal either way), or a remote MCP server's `url` uses `http://`/`ws://` with a host that isn't loopback (`localhost`, `127.0.0.0/8`, `::1`).",
  remediation: 'Enable TLS on the gateway and disable any plaintext fallback.',
  run(model) {
    const findings: Finding[] = [];
    if (model.gateway.present && model.gateway.tlsEnabled === false) {
      findings.push({
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'network',
        owasp: OWASP,
        message:
          'The gateway is configured with TLS disabled, so traffic (including any auth token) travels in plaintext.',
        location: {
          filePath: model.config.path,
          line: configLine(model, ['gateway', 'tls']),
          detail: 'gateway.tls',
        },
        remediation: 'Enable TLS on the gateway and disable any plaintext fallback.',
      });
    }
    for (const skill of model.skills) {
      const launch = skill.launch;
      if (launch?.kind !== 'remote') {
        continue;
      }
      const host = plaintextRemoteHost(launch.url);
      if (host === null) {
        continue;
      }
      const evidence = skill.capabilities.evidence.find((e) => e.capability === 'networkAccess');
      findings.push({
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'network',
        owasp: OWASP,
        message: `MCP server '${skill.name}' is reached over plaintext (${launch.url}), so its traffic, including any Authorization header, can be read or altered on the network.`,
        location: {
          filePath: skill.manifestPath,
          line: evidence?.line ?? null,
          detail: skill.name,
        },
        remediation: `Use an https:// (or wss://) URL for '${skill.name}'.`,
      });
    }
    return findings;
  },
};

/** The host of a plaintext, non-loopback URL; null for TLS, loopback, or an unparseable URL. */
function plaintextRemoteHost(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'ws:') {
    return null;
  }
  return isLoopbackAddress(parsed.hostname) ? null : parsed.hostname;
}
