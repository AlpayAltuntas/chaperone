import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapNet003PlaintextTransport } from '../../src/checks/network/chapNet003PlaintextTransport.js';
import { discoverAgent } from '../../src/discovery/index.js';
import type { AgentModel } from '../../src/model/types.js';

describe('CHAP-NET-003 — plaintext transport on the gateway', () => {
  it('fires on the vulnerable fixture (tls: false)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapNet003PlaintextTransport.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-NET-003');
    expect(findings[0]?.severity).toBe('medium');
  });

  it('stays silent on the clean fixture (tls: true)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapNet003PlaintextTransport.run(model)).toEqual([]);
  });

  it('stays silent when TLS is simply not mentioned in config (unknown, not a confident signal)', () => {
    const { model: base } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });
    const model: AgentModel = { ...base, gateway: { ...base.gateway, tlsEnabled: null } };

    expect(chapNet003PlaintextTransport.run(model)).toEqual([]);
  });
});
