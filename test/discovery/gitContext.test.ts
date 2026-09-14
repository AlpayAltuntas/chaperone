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

  it('finds an ancestor .git directory and reads root-level .gitignore lines', () => {
    mkdirSync(path.join(dir, '.git'));
    writeFileSync(path.join(dir, '.gitignore'), '# comment\nnode_modules/\n\n*.log\n');
    mkdirSync(path.join(dir, 'agent'), { recursive: true });
    const configPath = path.join(dir, 'agent', 'config.yaml');
    writeFileSync(configPath, 'a: 1\n');

    const context = detectGitContext(configPath);

    expect(context.hasAncestorGitDir).toBe(true);
    expect(context.gitRootPath).toBe(dir);
    expect(context.gitignorePatterns).toEqual(['node_modules/', '*.log']);
    expect(context.configPathRelativeToGitRoot).toBe(path.join('agent', 'config.yaml'));
  });

  it('reports no ancestor git dir when none exists up to the filesystem root', () => {
    const configPath = path.join(dir, 'config.yaml');
    writeFileSync(configPath, 'a: 1\n');

    const context = detectGitContext(configPath);

    expect(context.hasAncestorGitDir).toBe(false);
    expect(context.gitignorePatterns).toEqual([]);
  });

  it('treats a directory with no .gitignore as having an empty pattern list', () => {
    mkdirSync(path.join(dir, '.git'));
    const configPath = path.join(dir, 'config.yaml');
    writeFileSync(configPath, 'a: 1\n');

    const context = detectGitContext(configPath);

    expect(context.hasAncestorGitDir).toBe(true);
    expect(context.gitignorePatterns).toEqual([]);
  });
});
