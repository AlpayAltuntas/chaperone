import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { chapNet002WeakGatewayAuth } from '../../src/checks/network/chapNet002WeakGatewayAuth.js';
import { discoverAgent } from '../../src/discovery/index.js';
import type { AgentModel } from '../../src/model/types.js';

describe('CHAP-NET-002 — missing or weak auth on the gateway control API', () => {
  it('fires on the vulnerable fixture (empty auth token)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapNet002WeakGatewayAuth.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-NET-002');
    expect(findings[0]?.severity).toBe('high');
  });

  it('stays silent on the clean fixture (a real token is configured via env reference)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapNet002WeakGatewayAuth.run(model)).toEqual([]);
  });

  it('fires when no auth is configured at all', () => {
    const { model: base } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'clean-agent'),
    });
    const model: AgentModel = {
      ...base,
      gateway: { ...base.gateway, authConfigured: false, authTokenIsDefaultOrEmpty: null },
    };

    expect(chapNet002WeakGatewayAuth.run(model)).toHaveLength(1);
  });

  it('stays silent when there is no gateway at all', () => {
    const { model: base } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'clean-agent'),
    });
    const model: AgentModel = {
      ...base,
      gateway: {
        present: false,
        bindHost: null,
        port: null,
        authConfigured: null,
        authTokenIsDefaultOrEmpty: null,
        tlsEnabled: null,
      },
    };

    expect(chapNet002WeakGatewayAuth.run(model)).toEqual([]);
  });
});
