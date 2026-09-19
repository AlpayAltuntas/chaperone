import { describe, expect, it } from 'vitest';
import { isGitignored } from '../../../src/checks/shared/gitignoreMatch.js';
import type { GitignoreFile } from '../../../src/model/types.js';

function root(...patterns: string[]): GitignoreFile[] {
  return [{ dirRelativeToRoot: '', patterns }];
}

describe('isGitignored — single (root) .gitignore', () => {
  it('matches an exact root-anchored path', () => {
    expect(isGitignored('config.yaml', root('config.yaml'))).toBe(true);
  });

  it('matches a basename pattern at any depth', () => {
    expect(isGitignored('agent/config.yaml', root('config.yaml'))).toBe(true);
  });

  it('does not match an unrelated pattern', () => {
    expect(isGitignored('config.yaml', root('node_modules/', '*.log'))).toBe(false);
  });

  it('supports * wildcards', () => {
    expect(isGitignored('secrets.local.yaml', root('secrets.*.yaml'))).toBe(true);
  });

  it('a directory-only pattern matches a file nested inside that directory', () => {
    expect(isGitignored('config/local.yaml', root('config/'))).toBe(true);
  });

  it('a directory-only pattern requires isDirectory:true to match the directory itself', () => {
    expect(isGitignored('memory', root('memory/'))).toBe(false);
    expect(isGitignored('memory', root('memory/'), true)).toBe(true);
  });

  it('honors ! negation applied after a matching pattern', () => {
    expect(isGitignored('config.yaml', root('*.yaml', '!config.yaml'))).toBe(false);
  });

  it('returns false for an empty gitignore-files list', () => {
    expect(isGitignored('config.yaml', [])).toBe(false);
  });

  it('respects pattern order — a later match overrides an earlier one', () => {
    expect(isGitignored('config.yaml', root('!config.yaml', '*.yaml'))).toBe(true);
  });

  // improvement_plan.md 1.14 — previously unsupported by the hand-rolled
  // matcher.
  it('supports ** matching zero or more directories', () => {
    expect(isGitignored('a/b/c/secrets.yaml', root('a/**/secrets.yaml'))).toBe(true);
    expect(isGitignored('a/secrets.yaml', root('a/**/secrets.yaml'))).toBe(true);
    expect(isGitignored('x/secrets.yaml', root('a/**/secrets.yaml'))).toBe(false);
  });

  it('supports a leading ** matching any number of leading directories', () => {
    expect(isGitignored('a/b/c/build', root('**/build'))).toBe(true);
    expect(isGitignored('build', root('**/build'))).toBe(true);
  });
});

// improvement_plan.md 1.14 — nested .gitignore support: a pattern in a
// non-root .gitignore is scoped to its own directory, not applied
// repo-wide the way a root pattern would be.
describe('isGitignored — nested .gitignore files', () => {
  it("a nested file's bare pattern only applies within its own directory", () => {
    const files: GitignoreFile[] = [{ dirRelativeToRoot: 'agent', patterns: ['secrets.yaml'] }];

    expect(isGitignored('agent/secrets.yaml', files)).toBe(true);
    // Same basename, but outside the nested .gitignore's directory —
    // must NOT be covered by a rule scoped to a different directory.
    expect(isGitignored('other/secrets.yaml', files)).toBe(false);
    expect(isGitignored('secrets.yaml', files)).toBe(false);
  });

  it("a nested file's bare pattern applies at any depth within its own directory", () => {
    const files: GitignoreFile[] = [{ dirRelativeToRoot: 'agent', patterns: ['cache'] }];

    expect(isGitignored('agent/cache', files)).toBe(true);
    expect(isGitignored('agent/nested/cache', files)).toBe(true);
    expect(isGitignored('cache', files)).toBe(false);
  });

  it("a nested file's root-anchored pattern (/foo) anchors to its own directory, not deeper", () => {
    const files: GitignoreFile[] = [{ dirRelativeToRoot: 'agent', patterns: ['/build'] }];

    expect(isGitignored('agent/build', files)).toBe(true);
    expect(isGitignored('agent/nested/build', files)).toBe(false);
  });

  it('combines root and nested .gitignore patterns together', () => {
    const files: GitignoreFile[] = [
      { dirRelativeToRoot: '', patterns: ['*.log'] },
      { dirRelativeToRoot: 'agent', patterns: ['secrets.yaml'] },
    ];

    expect(isGitignored('debug.log', files)).toBe(true);
    expect(isGitignored('agent/secrets.yaml', files)).toBe(true);
    expect(isGitignored('agent/config.yaml', files)).toBe(false);
  });

  it('a nested .gitignore can negate a broader root pattern for its own directory', () => {
    const files: GitignoreFile[] = [
      { dirRelativeToRoot: '', patterns: ['*.yaml'] },
      { dirRelativeToRoot: 'agent', patterns: ['!config.yaml'] },
    ];

    expect(isGitignored('other/thing.yaml', files)).toBe(true);
    expect(isGitignored('agent/config.yaml', files)).toBe(false);
  });

  it('a directory-only nested pattern requires isDirectory:true to match the directory itself', () => {
    const files: GitignoreFile[] = [{ dirRelativeToRoot: 'agent', patterns: ['memory/'] }];

    expect(isGitignored('agent/memory', files)).toBe(false);
    expect(isGitignored('agent/memory', files, true)).toBe(true);
    expect(isGitignored('agent/memory/state.json', files)).toBe(true);
  });
});
