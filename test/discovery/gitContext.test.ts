import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { detectGitContext } from '../../src/discovery/gitContext.js';

describe('detectGitContext', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-git-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('finds an ancestor .git directory and reads the root .gitignore lines', () => {
    mkdirSync(path.join(dir, '.git'));
    writeFileSync(path.join(dir, '.gitignore'), '# comment\nnode_modules/\n\n*.log\n');
    mkdirSync(path.join(dir, 'agent'), { recursive: true });
    const configPath = path.join(dir, 'agent', 'config.yaml');
    writeFileSync(configPath, 'a: 1\n');

    const context = detectGitContext(configPath, path.join(dir, 'agent'));

    expect(context.hasAncestorGitDir).toBe(true);
    expect(context.gitRootPath).toBe(dir);
    expect(context.gitignoreFiles).toEqual([
      { dirRelativeToRoot: '', patterns: ['node_modules/', '*.log'] },
    ]);
    expect(context.configPathRelativeToGitRoot).toBe(path.join('agent', 'config.yaml'));
  });

  it('reports no ancestor git dir when none exists up to the filesystem root', () => {
    const configPath = path.join(dir, 'config.yaml');
    writeFileSync(configPath, 'a: 1\n');

    const context = detectGitContext(configPath, dir);

    expect(context.hasAncestorGitDir).toBe(false);
    expect(context.gitignoreFiles).toEqual([]);
  });

  it('treats a directory with no .gitignore as having an empty file list', () => {
    mkdirSync(path.join(dir, '.git'));
    const configPath = path.join(dir, 'config.yaml');
    writeFileSync(configPath, 'a: 1\n');

    const context = detectGitContext(configPath, dir);

    expect(context.hasAncestorGitDir).toBe(true);
    expect(context.gitignoreFiles).toEqual([]);
  });

  // improvement_plan.md 1.14: nested-.gitignore support. detectGitContext's
  // own job is just collecting every .gitignore between the git root and
  // targetRoot (inclusive) — the scoping/matching logic itself is tested
  // separately in gitignoreMatch.test.ts.
  it('collects .gitignore files at every level from the git root down to targetRoot', () => {
    mkdirSync(path.join(dir, '.git'));
    writeFileSync(path.join(dir, '.gitignore'), '*.log\n');
    mkdirSync(path.join(dir, 'agent', 'nested'), { recursive: true });
    writeFileSync(path.join(dir, 'agent', '.gitignore'), 'secrets.yaml\n');
    writeFileSync(path.join(dir, 'agent', 'nested', '.gitignore'), 'cache/\n');
    const configPath = path.join(dir, 'agent', 'nested', 'config.yaml');
    writeFileSync(configPath, 'a: 1\n');

    const context = detectGitContext(configPath, path.join(dir, 'agent', 'nested'));

    expect(context.gitignoreFiles).toEqual([
      { dirRelativeToRoot: '', patterns: ['*.log'] },
      { dirRelativeToRoot: 'agent', patterns: ['secrets.yaml'] },
      { dirRelativeToRoot: 'agent/nested', patterns: ['cache/'] },
    ]);
  });

  it('does not collect a .gitignore below targetRoot (out of scope)', () => {
    mkdirSync(path.join(dir, '.git'));
    mkdirSync(path.join(dir, 'agent', 'skills'), { recursive: true });
    writeFileSync(path.join(dir, 'agent', 'skills', '.gitignore'), 'node_modules/\n');
    const configPath = path.join(dir, 'agent', 'config.yaml');
    writeFileSync(configPath, 'a: 1\n');

    const context = detectGitContext(configPath, path.join(dir, 'agent'));

    expect(context.gitignoreFiles).toEqual([]);
  });

  it('only collects the root .gitignore when targetRoot is the git root itself', () => {
    mkdirSync(path.join(dir, '.git'));
    writeFileSync(path.join(dir, '.gitignore'), '*.log\n');
    const configPath = path.join(dir, 'config.yaml');
    writeFileSync(configPath, 'a: 1\n');

    const context = detectGitContext(configPath, dir);

    expect(context.gitignoreFiles).toEqual([{ dirRelativeToRoot: '', patterns: ['*.log'] }]);
  });
});
