import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSup006TyposquatRisk } from '../../src/checks/supplyChain/chapSup006TyposquatRisk.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SUP-006 — typosquat-risk dependency name', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sup006-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function writeSkill(name: string, dependencies: Record<string, string>): void {
    const skillDir = path.join(dir, 'skills', name);
    mkdirSync(skillDir, { recursive: true });
    writeFileSync(
      path.join(skillDir, 'package.json'),
      JSON.stringify({ name, version: '1.0.0', dependencies }),
    );
    writeFileSync(dir + '/config.yaml', 'skills_dir: ./skills\n');
  }

  it('fires on a dependency name one edit away from a well-known package (reqeust -> request)', () => {
    writeSkill('http-skill', { reqeust: '^2.88.0' });

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapSup006TyposquatRisk.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-SUP-006');
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.message).toContain("'reqeust'");
    expect(findings[0]?.message).toContain("'request'");
  });

  it('fires on another close typosquat (loadash -> lodash)', () => {
    writeSkill('utils-skill', { loadash: '^4.17.0' });

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSup006TyposquatRisk.run(model)).toHaveLength(1);
  });

  it('stays silent for the real, exact package name', () => {
    writeSkill('http-skill', { request: '^2.88.0' });

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSup006TyposquatRisk.run(model)).toEqual([]);
  });

  it('stays silent for an unrelated dependency name with no close match', () => {
    writeSkill('misc-skill', { 'my-internal-helper-lib': '^1.0.0' });

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSup006TyposquatRisk.run(model)).toEqual([]);
  });

  it('stays silent when a skill declares no dependencies at all', () => {
    const skillDir = path.join(dir, 'skills', 'no-deps');
    mkdirSync(skillDir, { recursive: true });
    writeFileSync(path.join(skillDir, 'package.json'), JSON.stringify({ name: 'no-deps' }));
    writeFileSync(path.join(dir, 'config.yaml'), 'skills_dir: ./skills\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapSup006TyposquatRisk.run(model)).toEqual([]);
  });
});
