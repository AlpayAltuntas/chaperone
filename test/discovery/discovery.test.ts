import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
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
    expect(model.skills).toHaveLength(6);

    const shellRunner = model.skills.find((s) => s.name === 'shell-runner');
    expect(shellRunner?.capabilities.shellExec).toBe(true);
    expect(shellRunner?.dependencies.lockfilePath).toBeNull();
    expect(shellRunner?.provenance.pinnedRef).toBe(false);
    expect(shellRunner?.installScripts.scripts.length).toBeGreaterThan(0);

    const webFetcher = model.skills.find((s) => s.name === 'web-fetcher');
    expect(webFetcher?.capabilities.networkAccess).toBe(true);
    expect(webFetcher?.capabilities.shellExec).toBe(false);

    // Phase 16 (improvement_plan.md 1.9): regex-based Python capability
    // detection, exercised end-to-end via discovery — not just against
    // detectPythonCapabilities directly.
    const pyCacheCleaner = model.skills.find((s) => s.name === 'py-cache-cleaner');
    expect(pyCacheCleaner?.capabilities.shellExec).toBe(true);
    expect(pyCacheCleaner?.capabilities.destructiveKeywords).toContain('delete');
    expect(pyCacheCleaner?.capabilities.networkAccess).toBe(false);
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
    expect(model.skills).toHaveLength(4);
    const notes = model.skills.find((s) => s.name === 'notes');
    expect(notes?.capabilities.shellExec).toBe(false);
    expect(notes?.capabilities.networkAccess).toBe(false);
    expect(notes?.capabilities.fileSystemScoped).toBe(true);
    expect(notes?.dependencies.lockfilePath).not.toBeNull();
    expect(notes?.provenance.pinnedRef).toBe(true);

    // Phase 16: the Python equivalent — writes only inside a scoped
    // workspace directory, so CHAP-AGY-002 (unrestricted filesystem)
    // correctly stays silent on it too (see chapAgy002.test.ts).
    const pyNotes = model.skills.find((s) => s.name === 'py-notes');
    expect(pyNotes?.capabilities.fileSystemAccess).toBe(true);
    expect(pyNotes?.capabilities.fileSystemScoped).toBe(true);
    expect(pyNotes?.capabilities.shellExec).toBe(false);
  });
});

describe('discoverAgent — graceful degradation', () => {
  it('reports a nonexistent explicit path as nothing scanned', () => {
    const { model, targetRootResolved } = discoverAgent({
      targetPath: '/nonexistent/chaperone-target-xyz',
    });

    expect(targetRootResolved).toBe(false);
    expect(model.config.path).toBeNull();
    expect(model.skipped).toEqual([
      { path: path.resolve('/nonexistent/chaperone-target-xyz'), reason: 'path does not exist' },
    ]);
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

// PROPOSED_FIXES.md 2.1: an explicit path that isn't an agent install is
// "nothing scanned", never an empty model that grades "A".
describe('discoverAgent — explicit target validation', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-target-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('reports an empty directory as nothing scanned', () => {
    const { model, targetRootResolved } = discoverAgent({ targetPath: dir });

    expect(targetRootResolved).toBe(false);
    expect(model.skipped).toHaveLength(1);
    expect(model.skipped[0]?.reason).toContain("doesn't look like an agent installation");
  });

  it('reports a non-config file as nothing scanned', () => {
    const file = path.join(dir, 'notes.txt');
    writeFileSync(file, 'hello\n');

    const { model, targetRootResolved } = discoverAgent({ targetPath: file });

    expect(targetRootResolved).toBe(false);
    expect(model.skipped[0]?.reason).toContain('path is a file, not an agent directory');
  });

  it.each(['config.yaml', 'config.json'])(
    'treats a path to %s itself as its containing directory',
    (filename) => {
      const file = path.join(dir, filename);
      writeFileSync(file, filename.endsWith('.json') ? '{}' : 'agent: {}\n');

      const { model, targetRootResolved } = discoverAgent({ targetPath: file });

      expect(targetRootResolved).toBe(true);
      expect(model.targetRoot).toBe(dir);
      expect(model.config.path).toBe(file);
    },
  );

  it('resolves a directory with a skills/ dir but no config, and notes the missing config', () => {
    mkdirSync(path.join(dir, 'skills'));

    const { model, targetRootResolved } = discoverAgent({ targetPath: dir });

    expect(targetRootResolved).toBe(true);
    expect(model.skipped.some((s) => s.reason.includes('no config.yaml/.yml/.json found'))).toBe(
      true,
    );
  });
});
