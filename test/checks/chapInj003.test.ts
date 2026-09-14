import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapInj003NoToolAllowlist } from '../../src/checks/injection/chapInj003NoToolAllowlist.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-INJ-003 — actions triggerable by inbound messages without an allowlist', () => {
  it('fires on the vulnerable fixture (active channel, empty tool_allowlist)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapInj003NoToolAllowlist.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-INJ-003');
    expect(findings[0]?.severity).toBe('high');
  });

  it('stays silent on the clean fixture (a non-empty tool_allowlist is configured)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapInj003NoToolAllowlist.run(model)).toEqual([]);
  });
});
