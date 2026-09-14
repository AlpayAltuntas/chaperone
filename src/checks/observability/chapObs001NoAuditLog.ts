import type { Check } from '../../engine/types.js';

const ID = 'CHAP-OBS-001';
const TITLE = 'No audit log of agent actions';
const OWASP = 'LLM08-adjacent';

/** Flags a missing or disabled audit log of tool invocations/actions. */
export const chapObs001NoAuditLog: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'observability',
  owasp: OWASP,
  run(model) {
    if (model.logging.present && model.logging.auditLogEnabled === true) {
      return [];
    }

    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'observability',
        owasp: OWASP,
        message: model.logging.present
          ? 'Logging is configured but the audit log of tool invocations/actions is disabled.'
          : 'No logging is configured at all, so there is no audit log of tool invocations/actions.',
        location: { filePath: model.config.path, line: null, detail: 'logging.audit.enabled' },
        remediation:
          'Enable an append-only audit log of every tool invocation/action the agent takes.',
      },
    ];
  },
};
