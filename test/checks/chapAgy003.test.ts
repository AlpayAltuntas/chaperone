import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapAgy003DestructiveWithoutConfirmation } from '../../src/checks/agency/chapAgy003DestructiveWithoutConfirmation.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-AGY-003 — destructive action without confirmation', () => {
  it('fires on the file-writer skill in the vulnerable fixture (can delete, no confirmation declared)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapAgy003DestructiveWithoutConfirmation.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-AGY-003');
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.location.detail).toBe('file-writer');
  });

  it('stays silent on the clean fixture (messenger can send, but confirmationRequired is declared)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapAgy003DestructiveWithoutConfirmation.run(model)).toEqual([]);
  });
});
