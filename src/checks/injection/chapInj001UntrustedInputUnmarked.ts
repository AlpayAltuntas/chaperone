import type { Check } from '../../engine/types.js';
import { getTrustBoolean, isAnyChannelEnabled } from '../shared/configAccess.js';

const ID = 'CHAP-INJ-001';
const TITLE = 'Untrusted input flows straight to the model';
const OWASP = 'LLM01: Prompt Injection';

/** Flags an active inbound channel with no trust-boundary marking configured for untrusted input. */
export const chapInj001UntrustedInputUnmarked: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'injection',
  owasp: OWASP,
  detects:
    'An active inbound message channel with no trust boundary separating untrusted content before it reaches the model.',
  heuristic:
    'At least one `channels.*.enabled` is `true` in config, and `trust.mark_untrusted_input` is not `true`.',
  remediation:
    'Mark untrusted inbound content explicitly, keep it separated from system instructions in the prompt, and filter it before forwarding to the model.',
  run(model) {
    if (model.config.path === null || !isAnyChannelEnabled(model.config.data)) {
      return [];
    }
    if (getTrustBoolean(model.config.data, 'mark_untrusted_input') === true) {
      return [];
    }

    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'high',
        category: 'injection',
        owasp: OWASP,
        message:
          'At least one inbound message channel is active, but config has no trust boundary marking untrusted content before it reaches the model.',
        location: { filePath: model.config.path, line: null, detail: 'trust.mark_untrusted_input' },
        remediation:
          'Mark untrusted inbound content explicitly and keep it separated from system instructions in the prompt; filter before forwarding it to the model.',
      },
    ];
  },
};
