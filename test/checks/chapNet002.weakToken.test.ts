import { describe, expect, it } from 'vitest';
import { chapNet002WeakGatewayAuth } from '../../src/checks/network/chapNet002WeakGatewayAuth.js';
import { extractGatewayModel } from '../../src/discovery/gateway.js';
import { discoverAgent } from '../../src/discovery/index.js';

// PROPOSED_FIXES.md 3.8.
function weakness(token: string, extra: Record<string, unknown> = {}): string | null {
  return extractGatewayModel({ ...extra, gateway: { host: '0.0.0.0', auth: { token } } })
    .authTokenWeakness;
}

describe('gateway token weakness', () => {
  it.each([
    ['', 'empty'],
    ['ChangeMe', 'default'],
    ['abc', 'short'],
    ['secret123', 'short'],
    ['a-very-long-random-token-value-123', null],
    ['${GW_TOKEN}', null],
  ])('%j -> %s', (token, expected) => {
    expect(weakness(token)).toBe(expected);
  });

  it('reports a token reused from another secret in the config', () => {
    const token = 'shared-secret-value-long-enough-1';
    expect(weakness(token, { llm: { api_key: token } })).toBe('reused');
  });
});

describe('CHAP-NET-002 severity by bind address', () => {
  function run(host: string): ReturnType<typeof chapNet002WeakGatewayAuth.run> {
    const { model } = discoverAgent({ targetPath: 'test/fixtures/clean-agent' });
    return chapNet002WeakGatewayAuth.run({
      ...model,
      gateway: { ...extractGatewayModel({ gateway: { host, auth: { token: 'abc' } } }) },
    });
  }

  it('is high on a non-loopback bind and medium on loopback', () => {
    expect(run('0.0.0.0')).toMatchObject([{ severity: 'high' }]);
    const local = run('127.0.0.1:8080');
    expect(local).toMatchObject([{ severity: 'medium' }]);
    expect(local[0]?.message).toContain('shorter than 16 characters');
    expect(local[0]?.message).toContain('DNS rebinding');
  });
});
