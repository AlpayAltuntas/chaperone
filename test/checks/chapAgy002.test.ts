import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapAgy002UnrestrictedFilesystem } from '../../src/checks/agency/chapAgy002UnrestrictedFilesystem.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-AGY-002 — unrestricted filesystem access', () => {
  it('fires on the file-writer skill in the vulnerable fixture (unscoped fs access)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapAgy002UnrestrictedFilesystem.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-AGY-002');
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.location.detail).toBe('file-writer');
  });

  it('stays silent on the clean fixture (notes skill is scoped to its own workspace dir)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapAgy002UnrestrictedFilesystem.run(model)).toEqual([]);
  });
});
