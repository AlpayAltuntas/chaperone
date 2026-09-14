import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapInj004AutoExecuteFromMessages } from '../../src/checks/injection/chapInj004AutoExecuteFromMessages.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-INJ-004 — auto-execution of links/commands from messages', () => {
  it('fires on the vulnerable fixture (auto_execute_links is true)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapInj004AutoExecuteFromMessages.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-INJ-004');
    expect(findings[0]?.severity).toBe('high');
  });

  it('stays silent on the clean fixture (auto_execute_links is false)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapInj004AutoExecuteFromMessages.run(model)).toEqual([]);
  });
});
