import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { discoverAgent } from '../../src/discovery/index.js';

const VULNERABLE_FIXTURE = path.join('test', 'fixtures', 'vulnerable-agent');
const CLEAN_FIXTURE = path.join('test', 'fixtures', 'clean-agent');

describe('discoverAgent — vulnerable-agent fixture', () => {
  const { model, targetRootResolved } = discoverAgent({ targetPath: VULNERABLE_FIXTURE });

  it('resolves the target root and locates the config file', () => {
    expect(targetRootResolved).toBe(true);
    expect(model.config.path).not.toBeNull();
    expect(model.config.format).toBe('yaml');
  });

  it('masks literal secrets and never retains the real value', () => {
    const apiKey = model.config.secretFields.find((f) => f.keyPath === 'llm.api_key');
    expect(apiKey).toBeDefined();
    expect(apiKey?.looksLikeEnvReference).toBe(false);
    expect(apiKey?.displayValue).not.toContain('EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz');
    expect(apiKey?.displayValue).toMatch(/^sk…|…/);

    const serialized = JSON.stringify(model);
    expect(serialized).not.toContain('EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz');
  });

  it('reports the gateway bound beyond localhost with a weak auth token', () => {
    expect(model.gateway.present).toBe(true);
    expect(model.gateway.bindHost).toBe('0.0.0.0');
    expect(model.gateway.authTokenIsDefaultOrEmpty).toBe(true);
    expect(model.gateway.tlsEnabled).toBe(false);
  });

  it('discovers all skills with their capabilities', () => {
    expect(model.skills).toHaveLength(4);

    const shellRunner = model.skills.find((s) => s.name === 'shell-runner');
    expect(shellRunner?.capabilities.shellExec).toBe(true);
    expect(shellRunner?.dependencies.lockfilePath).toBeNull();
    expect(shellRunner?.provenance.pinnedRef).toBe(false);
    expect(shellRunner?.installScripts.scripts.length).toBeGreaterThan(0);

    const webFetcher = model.skills.find((s) => s.name === 'web-fetcher');
    expect(webFetcher?.capabilities.networkAccess).toBe(true);
    expect(webFetcher?.capabilities.shellExec).toBe(false);
  });

  it('flags the config as sitting under an ancestor git repo', () => {
    expect(model.git.hasAncestorGitDir).toBe(true);
    expect(model.git.configPathRelativeToGitRoot).toContain('vulnerable-agent');
  });
});

describe('discoverAgent — clean-agent fixture', () => {
  const { model } = discoverAgent({ targetPath: CLEAN_FIXTURE });

  it('finds no literal secrets, only env references', () => {
    expect(model.config.secretFields.length).toBeGreaterThan(0);
    expect(model.config.secretFields.every((f) => f.looksLikeEnvReference)).toBe(true);
  });

  it('reports the gateway bound to localhost with TLS and a non-weak token', () => {
    expect(model.gateway.bindHost).toBe('127.0.0.1');
    expect(model.gateway.authTokenIsDefaultOrEmpty).toBe(false);
    expect(model.gateway.tlsEnabled).toBe(true);
  });

  it('discovers the notes skill with no shell/network capability', () => {
    expect(model.skills).toHaveLength(3);
    const notes = model.skills.find((s) => s.name === 'notes');
    expect(notes?.capabilities.shellExec).toBe(false);
    expect(notes?.capabilities.networkAccess).toBe(false);
    expect(notes?.capabilities.fileSystemScoped).toBe(true);
    expect(notes?.dependencies.lockfilePath).not.toBeNull();
    expect(notes?.provenance.pinnedRef).toBe(true);
  });
});

describe('discoverAgent — graceful degradation', () => {
  it('does not throw and reports a skipped entry for a nonexistent target', () => {
    const { model, targetRootResolved } = discoverAgent({
      targetPath: '/nonexistent/chaperone-target-xyz',
    });

    expect(targetRootResolved).toBe(true); // explicit path always "resolves" to an absolute path
    expect(model.config.path).toBeNull();
    expect(model.skipped.length).toBeGreaterThan(0);
    expect(model.skills).toEqual([]);
  });

  it('does not throw when no default install location exists and no path is given', () => {
    expect(() => discoverAgent({})).not.toThrow();
  });

  it('explains which default locations it tried and how to pass an explicit path', () => {
    const { model, targetRootResolved } = discoverAgent({});

    expect(targetRootResolved).toBe(false);
    expect(model.skipped).toHaveLength(1);
    const reason = model.skipped[0]?.reason ?? '';
    expect(reason).toContain('no agent installation found at any default location');
    expect(reason).toContain('.clawd');
    expect(reason).toContain('chaperone scan <path>');
  });
});
