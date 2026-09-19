import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapAgy004BroadNetworkEgress } from '../../src/checks/agency/chapAgy004BroadNetworkEgress.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-AGY-004 — broad network egress from a skill', () => {
  it('fires on every network-capable skill with no domain allowlist in the vulnerable fixture', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapAgy004BroadNetworkEgress.run(model);

    expect(findings).toHaveLength(3);
    const skillNames = findings.map((f) => f.location.detail).sort();
    expect(skillNames).toEqual(['command-relay', 'plugin-loader', 'web-fetcher']);
  });

  it('stays silent on the clean fixture (weather skill declares a domain allowlist)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapAgy004BroadNetworkEgress.run(model)).toEqual([]);
  });
});
