import type { Check } from '../../engine/types.js';

const ID = 'CHAP-OBS-003';
const TITLE = 'No documented kill switch / revocation path';
const OWASP = 'General';

/** Flags the absence of a documented kill-switch/revocation file at the install root (see recoverability.ts for the naming convention checked). */
export const chapObs003NoKillSwitch: Check = {
  id: ID,
  title: TITLE,
  severity: 'low',
  category: 'observability',
  owasp: OWASP,
  detects: 'No documented quick way to stop the agent and revoke its access.',
  heuristic:
    "None of `KILL_SWITCH.md`, `STOP.md`, `kill-switch.sh`, or `revoke.sh` exists at the install root — a documented, invented naming convention (no real spec exists for this); an install documenting a kill switch any other way won't be detected in v1.",
  remediation:
    'Document a kill switch (how to stop the agent) and a script or checklist to revoke/rotate its credentials.',
  run(model) {
    if (model.recoverability.killSwitchDocumented) {
      return [];
    }

    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'low',
        category: 'observability',
        owasp: OWASP,
        message:
          'No documented quick way to stop the agent and revoke its access was found at the install root.',
        location: {
          filePath: model.targetRoot,
          line: null,
          detail: 'KILL_SWITCH.md / STOP.md / kill-switch.sh / revoke.sh',
        },
        remediation:
          'Document a kill switch (how to stop the agent) and a script or checklist to revoke/rotate its credentials.',
      },
    ];
  },
};
