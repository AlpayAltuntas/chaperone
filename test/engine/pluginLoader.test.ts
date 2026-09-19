import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadPlugin, loadPlugins, mergeChecks } from '../../src/engine/pluginLoader.js';
import type { Check } from '../../src/engine/types.js';

const SAMPLE_PLUGIN_PATH = path.join('test', 'fixtures', 'plugins', 'samplePlugin.cjs');
const INVALID_PLUGIN_PATH = path.join('test', 'fixtures', 'plugins', 'invalidPlugin.cjs');
const DUPLICATE_ID_PLUGIN_PATH = path.join('test', 'fixtures', 'plugins', 'duplicateIdPlugin.cjs');

function makeCheck(overrides: Partial<Check> = {}): Check {
  return {
    id: 'CHAP-TEST-000',
    title: 'test',
    severity: 'info',
    category: 'secrets',
    owasp: 'LLM06',
    detects: 'n/a',
    heuristic: 'n/a',
    remediation: 'n/a',
    run: () => [],
    ...overrides,
  };
}

describe('loadPlugin', () => {
  it('loads a real CommonJS plugin module and returns its checks', () => {
    const { path: loadedPath, checks } = loadPlugin(SAMPLE_PLUGIN_PATH);

    expect(loadedPath).toBe(SAMPLE_PLUGIN_PATH);
    expect(checks).toHaveLength(1);
    expect(checks[0]?.id).toBe('CHAP-CUSTOM-001');
    expect(typeof checks[0]?.run).toBe('function');
  });

  it('the loaded check actually runs and produces a real finding', () => {
    const { checks } = loadPlugin(SAMPLE_PLUGIN_PATH);
    const check = checks[0];
    if (check === undefined) {
      throw new Error('expected samplePlugin.cjs to export one check');
    }

    const model = {
      skills: [{ name: 'my-experimental-skill', manifestPath: '/fake/package.json' }],
    } as never;

    const findings = check.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-CUSTOM-001');
    expect(findings[0]?.message).toContain('my-experimental-skill');
  });

  it('throws a clear error for a nonexistent plugin path', () => {
    expect(() => loadPlugin('does/not/exist.cjs')).toThrow(/could not load plugin/);
  });

  it('throws a clear error when the module does not export a valid Check shape', () => {
    expect(() => loadPlugin(INVALID_PLUGIN_PATH)).toThrow(/does not export a valid Check/);
  });

  it('throws a clear error when the module exports nothing usable at all', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-plugin-test-'));
    try {
      const emptyPath = path.join(dir, 'empty.cjs');
      writeFileSync(emptyPath, 'module.exports = undefined;\n');

      expect(() => loadPlugin(emptyPath)).toThrow(/does not export a valid Check/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('accepts an array of checks as the default export', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-plugin-test-'));
    try {
      const arrayPluginPath = path.join(dir, 'array-plugin.cjs');
      writeFileSync(
        arrayPluginPath,
        `module.exports = [
          { id: 'CHAP-CUSTOM-A', title: 'a', severity: 'low', category: 'secrets', owasp: 'x', detects: 'x', heuristic: 'x', remediation: 'x', run: () => [] },
          { id: 'CHAP-CUSTOM-B', title: 'b', severity: 'low', category: 'secrets', owasp: 'x', detects: 'x', heuristic: 'x', remediation: 'x', run: () => [] },
        ];`,
      );

      const { checks } = loadPlugin(arrayPluginPath);

      expect(checks.map((c) => c.id)).toEqual(['CHAP-CUSTOM-A', 'CHAP-CUSTOM-B']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('loadPlugins', () => {
  it('flattens checks from multiple plugins, in order', () => {
    const checks = loadPlugins([SAMPLE_PLUGIN_PATH]);
    expect(checks.map((c) => c.id)).toEqual(['CHAP-CUSTOM-001']);
  });

  it('returns an empty array for an empty plugin list', () => {
    expect(loadPlugins([])).toEqual([]);
  });
});

describe('mergeChecks', () => {
  it('concatenates built-in and plugin checks when there is no ID collision', () => {
    const builtIn = [makeCheck({ id: 'CHAP-SEC-001' })];
    const plugin = [makeCheck({ id: 'CHAP-CUSTOM-001' })];

    expect(mergeChecks(builtIn, plugin).map((c) => c.id)).toEqual([
      'CHAP-SEC-001',
      'CHAP-CUSTOM-001',
    ]);
  });

  it('throws when a plugin check ID collides with a built-in one', () => {
    const builtIn = [makeCheck({ id: 'CHAP-SEC-001' })];
    const plugin = [makeCheck({ id: 'CHAP-SEC-001' })];

    expect(() => mergeChecks(builtIn, plugin)).toThrow(/collides with a built-in check/);
  });

  it('throws when two plugins declare the same check ID', () => {
    const builtIn: Check[] = [];
    const pluginA = loadPlugin(DUPLICATE_ID_PLUGIN_PATH).checks;
    const pluginB = loadPlugin(DUPLICATE_ID_PLUGIN_PATH).checks;

    expect(() => mergeChecks(builtIn, [...pluginA, ...pluginB])).toThrow(/collides with/);
  });

  it('the real duplicateIdPlugin fixture collides with the real CHAP-SEC-001', async () => {
    const { ALL_CHECKS } = await import('../../src/checks/index.js');
    const pluginChecks = loadPlugin(DUPLICATE_ID_PLUGIN_PATH).checks;

    expect(() => mergeChecks(ALL_CHECKS, pluginChecks)).toThrow(
      "plugin check ID 'CHAP-SEC-001' collides with a built-in check",
    );
  });
});
