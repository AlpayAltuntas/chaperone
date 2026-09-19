import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapObs001NoAuditLog } from '../../src/checks/observability/chapObs001NoAuditLog.js';
import { discoverAgent } from '../../src/discovery/index.js';
import type { AgentModel } from '../../src/model/types.js';

describe('CHAP-OBS-001 — no audit log of agent actions', () => {
  it('fires on the vulnerable fixture (audit.enabled: false)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapObs001NoAuditLog.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-OBS-001');
    expect(findings[0]?.severity).toBe('medium');
  });

  it('stays silent on the clean fixture (audit.enabled: true)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapObs001NoAuditLog.run(model)).toEqual([]);
  });

  it('fires when there is no logging config at all', () => {
    const { model: base } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'clean-agent'),
    });
    const model: AgentModel = {
      ...base,
      logging: {
        present: false,
        level: null,
        path: null,
        redactSecrets: null,
        auditLogEnabled: null,
        existingSecretMatches: [],
      },
    };

    expect(chapObs001NoAuditLog.run(model)).toHaveLength(1);
  });
});
