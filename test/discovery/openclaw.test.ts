import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { blankJson5 } from '../../src/discovery/configParser.js';
import { extractGatewayModel } from '../../src/discovery/gateway.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { runChecks } from '../../src/engine/index.js';
import { setConfigValues } from '../../src/fix/configEdit.js';

// PROPOSED_FIXES.md 6.2: OpenClaw's real config file and gateway keys.
const FIXTURE = path.join('test', 'fixtures', 'openclaw-agent');

describe('openclaw.json (JSON5)', () => {
  it('is discovered and parsed, with line numbers', () => {
    const { model, targetRootResolved } = discoverAgent({ targetPath: FIXTURE });
    expect(targetRootResolved).toBe(true);
    expect(model.config.path).toMatch(/openclaw\.json$/);
    expect(model.gateway).toMatchObject({
      bindHost: '0.0.0.0',
      authConfigured: true,
      authTokenWeakness: 'short',
    });
    expect(model.config.keyLines['gateway.bind']).toBe(6);
  });

  it('reports the exposed gateway and the weak password at their lines', () => {
    const { model } = discoverAgent({ targetPath: FIXTURE });
    const findings = runChecks(model, ALL_CHECKS, { profile: 'default' }).findings;
    expect(findings.find((f) => f.checkId === 'CHAP-NET-001')?.severity).toBe('critical');
    expect(findings.find((f) => f.checkId === 'CHAP-NET-002')).toMatchObject({ severity: 'high' });
    expect(
      findings.some(
        (f) => f.checkId === 'CHAP-SEC-001' && f.location.detail === 'gateway.auth.password',
      ),
    ).toBe(true);
  });
});

describe('gateway bind modes', () => {
  it.each([
    ['loopback', {}, '127.0.0.1'],
    ['lan', {}, '0.0.0.0'],
    ['custom', { customBindHost: '10.0.0.5' }, '10.0.0.5'],
    ['tailnet', {}, null],
    ['auto', {}, null],
  ])('%s -> %s', (bind, extra, host) => {
    expect(extractGatewayModel({ gateway: { bind, ...extra } }).bindHost).toBe(host);
  });

  it('treats auth.mode "none" as no auth', () => {
    expect(
      extractGatewayModel({ gateway: { bind: 'lan', auth: { mode: 'none' } } }).authConfigured,
    ).toBe(false);
  });
});

describe('blankJson5', () => {
  it('keeps length and lines, and leaves strings alone', () => {
    const source = '{\n  a: "x // not a comment", // comment\n  b: [1, 2,], /* c */\n}';
    const blanked = blankJson5(source);
    expect(blanked).toHaveLength(source.length);
    expect(blanked.split('\n')).toHaveLength(source.split('\n').length);
    expect(blanked).toContain('"x // not a comment"');
    expect(blanked).not.toContain('comment\n');
  });

  it('passes strict JSON through unchanged', () => {
    const json = JSON.stringify({ a: [1, 2], b: { c: 'd' } }, null, 2);
    expect(blankJson5(json)).toBe(json);
  });
});

describe('fixing an openclaw.json in place', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-openclaw-fix-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('keeps comments when setting a value', () => {
    const source = '{\n  // keep me\n  gateway: { bind: "lan", host: "0.0.0.0" },\n}\n';
    writeFileSync(path.join(dir, 'openclaw.json'), source);
    const out = setConfigValues(source, 'json', [{ keyPath: 'gateway.host', value: '127.0.0.1' }]);
    expect(out).toBe('{\n  // keep me\n  gateway: { bind: "lan", host: "127.0.0.1" },\n}\n');
  });
});
