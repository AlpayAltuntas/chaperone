import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapAgy003DestructiveWithoutConfirmation } from '../../src/checks/agency/chapAgy003DestructiveWithoutConfirmation.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-AGY-003 — destructive action without confirmation', () => {
  it('fires on skills with a destructive keyword and no confirmation declared, in the vulnerable fixture', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapAgy003DestructiveWithoutConfirmation.run(model);

    // file-writer (JS: fs.unlink) and py-cache-cleaner (Python, Phase 16:
    // a shell command deleting cache files, regex-detected).
    const skillNames = findings.map((f) => f.location.detail).sort();
    expect(skillNames).toEqual(['file-writer', 'py-cache-cleaner']);
    for (const finding of findings) {
      expect(finding.checkId).toBe('CHAP-AGY-003');
      expect(finding.severity).toBe('high');
    }
  });

  it('stays silent on the clean fixture (messenger can send, but confirmationRequired is declared)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapAgy003DestructiveWithoutConfirmation.run(model)).toEqual([]);
  });
});
