import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  chapNet001GatewayExposed,
  isLoopbackAddress,
} from '../../src/checks/network/chapNet001GatewayExposed.js';
import { discoverAgent } from '../../src/discovery/index.js';
import type { AgentModel } from '../../src/model/types.js';

const BASE_MODEL: AgentModel = {
  targetRoot: '/fake',
  config: { path: '/fake/config.yaml', format: 'yaml', data: null, secretFields: [] },
  sidecarSecretFiles: [],
  git: {
    hasAncestorGitDir: false,
    gitDirPath: null,
    gitRootPath: null,
    gitignorePatterns: [],
    configPathRelativeToGitRoot: null,
  },
  permissions: [],
  skills: [],
  gateway: {
    present: true,
    bindHost: '0.0.0.0',
    port: 18789,
    authConfigured: true,
    authTokenIsDefaultOrEmpty: false,
    tlsEnabled: true,
  },
  logging: {
    present: false,
    level: null,
    path: null,
    redactSecrets: null,
    auditLogEnabled: null,
    existingSecretMatches: [],
  },
  memory: { present: false, dir: null },
  recoverability: { killSwitchDocumented: false },
  inspected: [],
  skipped: [],
};

describe('CHAP-NET-001 — gateway bound beyond localhost', () => {
  it('fires on the vulnerable fixture (bound to 0.0.0.0)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapNet001GatewayExposed.run(model);

    expect(findings).toHaveLength(1);
    const [finding] = findings;
    expect(finding?.checkId).toBe('CHAP-NET-001');
    expect(finding?.severity).toBe('critical');
    expect(finding?.category).toBe('network');
    expect(finding?.location.detail).toBe('gateway.host');
    expect(finding?.location.filePath).toBe(model.config.path);
  });

  it('stays silent on the clean fixture (bound to 127.0.0.1)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapNet001GatewayExposed.run(model)).toEqual([]);
  });

  it('stays silent when there is no gateway configured at all', () => {
    const model: AgentModel = {
      ...BASE_MODEL,
      gateway: {
        present: false,
        bindHost: null,
        port: null,
        authConfigured: null,
        authTokenIsDefaultOrEmpty: null,
        tlsEnabled: null,
      },
    };

    expect(chapNet001GatewayExposed.run(model)).toEqual([]);
  });

  it.each(['127.0.0.1', 'localhost', 'LOCALHOST', '::1'])('treats %s as safe', (bindHost) => {
    const model: AgentModel = { ...BASE_MODEL, gateway: { ...BASE_MODEL.gateway, bindHost } };

    expect(chapNet001GatewayExposed.run(model)).toEqual([]);
  });

  // Regression tests for improvement_plan.md 1.3: previously only the
  // exact literal '127.0.0.1' was recognized, even though every address
  // in 127.0.0.0/8 is equally loopback-only, and IPv6 loopback written in
  // expanded form wasn't recognized either.
  it.each(['127.0.0.2', '127.1.2.3', '127.255.255.254'])(
    'treats %s (elsewhere in the loopback 127.0.0.0/8 block) as safe',
    (bindHost) => {
      const model: AgentModel = { ...BASE_MODEL, gateway: { ...BASE_MODEL.gateway, bindHost } };

      expect(chapNet001GatewayExposed.run(model)).toEqual([]);
    },
  );

  it.each(['0:0:0:0:0:0:0:1', '0000:0000:0000:0000:0000:0000:0000:0001'])(
    'treats %s (IPv6 loopback in expanded form) as safe',
    (bindHost) => {
      const model: AgentModel = { ...BASE_MODEL, gateway: { ...BASE_MODEL.gateway, bindHost } };

      expect(chapNet001GatewayExposed.run(model)).toEqual([]);
    },
  );

  it.each(['0.0.0.0', '192.168.1.1', '::', 'fe80::1'])(
    'still flags %s as exposed (not loopback)',
    (bindHost) => {
      const model: AgentModel = { ...BASE_MODEL, gateway: { ...BASE_MODEL.gateway, bindHost } };

      expect(chapNet001GatewayExposed.run(model)).toHaveLength(1);
    },
  );
});

describe('isLoopbackAddress', () => {
  it.each([
    'localhost',
    'LOCALHOST',
    '127.0.0.1',
    '127.0.0.2',
    '127.1.2.3',
    '127.255.255.254',
    '::1',
    '0:0:0:0:0:0:0:1',
    '0000:0000:0000:0000:0000:0000:0000:0001',
  ])('%s is loopback', (host) => {
    expect(isLoopbackAddress(host)).toBe(true);
  });

  it.each(['0.0.0.0', '192.168.1.1', '10.0.0.5', '::', '::0', 'fe80::1', 'example.com'])(
    '%s is not loopback',
    (host) => {
      expect(isLoopbackAddress(host)).toBe(false);
    },
  );
});
