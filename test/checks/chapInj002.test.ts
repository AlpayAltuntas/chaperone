import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapInj002ToolOutputTrusted } from '../../src/checks/injection/chapInj002ToolOutputTrusted.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-INJ-002 — tool output treated as trusted', () => {
  it('fires on the command-relay skill in the vulnerable fixture (fetches then shell-execs)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapInj002ToolOutputTrusted.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-INJ-002');
    expect(findings[0]?.location.detail).toBe('command-relay');
  });

  it('stays silent on the clean fixture (no skill combines ingestion with shell execution)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapInj002ToolOutputTrusted.run(model)).toEqual([]);
  });
});
