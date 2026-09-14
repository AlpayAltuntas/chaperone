import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapObs002UnredactedLogs } from '../../src/checks/observability/chapObs002UnredactedLogs.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-OBS-002 — sensitive data in plaintext logs', () => {
  it('fires on the vulnerable fixture (redact_secrets: false)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapObs002UnredactedLogs.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-OBS-002');
    expect(findings[0]?.severity).toBe('medium');
  });

  it('stays silent on the clean fixture (redact_secrets: true)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapObs002UnredactedLogs.run(model)).toEqual([]);
  });
});
