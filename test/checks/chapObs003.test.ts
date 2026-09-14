import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapObs003NoKillSwitch } from '../../src/checks/observability/chapObs003NoKillSwitch.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-OBS-003 — no documented kill switch / revocation path', () => {
  it('fires on the vulnerable fixture (no KILL_SWITCH.md/STOP.md at the root)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapObs003NoKillSwitch.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-OBS-003');
    expect(findings[0]?.severity).toBe('low');
  });

  it('stays silent on the clean fixture (KILL_SWITCH.md documents one)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapObs003NoKillSwitch.run(model)).toEqual([]);
  });
});
