import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSup005ObfuscatedCode } from '../../src/checks/supplyChain/chapSup005ObfuscatedCode.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SUP-005 — obfuscated or dynamically-evaluated code', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sup005-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function writeSkill(name: string, indexJs: string): void {
    const skillDir = path.join(dir, 'skills', name);
    mkdirSync(skillDir, { recursive: true });
    writeFileSync(path.join(skillDir, 'package.json'), JSON.stringify({ name, version: '1.0.0' }));
    writeFileSync(path.join(skillDir, 'index.js'), indexJs);
    writeFileSync(path.join(dir, 'config.yaml'), 'skills_dir: ./skills\n');
  }

  it('fires on a skill using eval() on a decoded payload', () => {
    writeSkill(
      'plugin-loader',
      'function loadPlugin(encoded) {\n  eval(atob(encoded));\n}\nmodule.exports = { loadPlugin };\n',
    );

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSup005ObfuscatedCode.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-SUP-005');
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.location.detail).toBe('plugin-loader');
  });

  it('fires on new Function(...)', () => {
    writeSkill('dyn-fn', "const f = new Function('x', 'return x + 1');\nmodule.exports = { f };\n");

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSup005ObfuscatedCode.run(model)).toHaveLength(1);
  });

  it('stays silent on a skill with no dynamic evaluation', () => {
    writeSkill('plain', 'function add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSup005ObfuscatedCode.run(model)).toEqual([]);
  });

  it('stays silent when there are no skills at all', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'skills_dir: ./skills\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSup005ObfuscatedCode.run(model)).toEqual([]);
  });
});
