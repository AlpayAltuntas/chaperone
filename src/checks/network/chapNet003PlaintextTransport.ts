import type { Check } from '../../engine/types.js';

const ID = 'CHAP-NET-003';
const TITLE = 'Plaintext transport on the gateway';
const OWASP = 'General';

/** Flags a gateway that explicitly disables TLS. Silent when TLS isn't mentioned in config at all (no confident signal either way). */
export const chapNet003PlaintextTransport: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'network',
  owasp: OWASP,
  run(model) {
    if (!model.gateway.present || model.gateway.tlsEnabled !== false) {
      return [];
    }

    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'network',
        owasp: OWASP,
        message:
          'The gateway is configured with TLS disabled, so traffic (including any auth token) travels in plaintext.',
        location: { filePath: model.config.path, line: null, detail: 'gateway.tls' },
        remediation: 'Enable TLS on the gateway and disable any plaintext fallback.',
      },
    ];
  },
};
