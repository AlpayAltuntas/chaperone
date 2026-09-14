import type { Check } from '../../engine/types.js';
import { getTrustBoolean } from '../shared/configAccess.js';

const ID = 'CHAP-INJ-004';
const TITLE = 'Auto-execution of links/commands from messages';
const OWASP = 'LLM01: Prompt Injection';

/** Flags config that auto-opens links or auto-runs commands found in inbound messages. */
export const chapInj004AutoExecuteFromMessages: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'injection',
  owasp: OWASP,
  run(model) {
    if (
      model.config.path === null ||
      getTrustBoolean(model.config.data, 'auto_execute_links') !== true
    ) {
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
          'Config auto-executes links/commands found in inbound messages with no confirmation step.',
        location: { filePath: model.config.path, line: null, detail: 'trust.auto_execute_links' },
        remediation:
          'Disable auto-execution of links/commands found in messages; require explicit confirmation instead.',
      },
    ];
  },
};
