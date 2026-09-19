import type { Check } from '../../engine/types.js';
import { getTrustToolAllowlist, isAnyChannelEnabled } from '../shared/configAccess.js';

const ID = 'CHAP-INJ-003';
const TITLE = 'Actions triggerable by inbound messages without an allowlist';
const OWASP = 'LLM01: Prompt Injection / LLM08: Excessive Agency';

/** Flags an active inbound channel with no channel/sender-to-tool allowlist restricting what it can invoke. */
export const chapInj003NoToolAllowlist: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'injection',
  owasp: OWASP,
  detects: 'Any inbound message being able to invoke any tool.',
  heuristic:
    'At least one channel is active and `trust.tool_allowlist` is empty or absent (same manifest-convention caveat as CHAP-AGY-003/004).',
  remediation: 'Restrict which tools each channel/sender can invoke with an explicit allowlist.',
  run(model) {
    if (model.config.path === null || !isAnyChannelEnabled(model.config.data)) {
      return [];
    }
    const allowlist = getTrustToolAllowlist(model.config.data);
    if (allowlist !== null && allowlist.length > 0) {
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
          'At least one inbound message channel is active, but no channel/sender-to-tool allowlist restricts which tools an inbound message can invoke.',
        location: { filePath: model.config.path, line: null, detail: 'trust.tool_allowlist' },
        remediation:
          'Restrict which tools each channel/sender can invoke with an explicit allowlist.',
      },
    ];
  },
};
