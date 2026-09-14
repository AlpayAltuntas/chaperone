import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapInj001UntrustedInputUnmarked } from '../../src/checks/injection/chapInj001UntrustedInputUnmarked.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-INJ-001 — untrusted input flows straight to the model', () => {
  it('fires on the vulnerable fixture (active channel, no trust boundary marking)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapInj001UntrustedInputUnmarked.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-INJ-001');
    expect(findings[0]?.severity).toBe('high');
  });

  it('stays silent on the clean fixture (mark_untrusted_input is true)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapInj001UntrustedInputUnmarked.run(model)).toEqual([]);
  });
});
