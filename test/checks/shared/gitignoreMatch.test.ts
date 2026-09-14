import { describe, expect, it } from 'vitest';
import { isGitignored } from '../../../src/checks/shared/gitignoreMatch.js';

describe('isGitignored', () => {
  it('matches an exact root-anchored path', () => {
    expect(isGitignored('config.yaml', ['config.yaml'])).toBe(true);
  });

  it('matches a basename pattern at any depth', () => {
    expect(isGitignored('agent/config.yaml', ['config.yaml'])).toBe(true);
  });

  it('does not match an unrelated pattern', () => {
    expect(isGitignored('config.yaml', ['node_modules/', '*.log'])).toBe(false);
  });

  it('supports * wildcards', () => {
    expect(isGitignored('secrets.local.yaml', ['secrets.*.yaml'])).toBe(true);
  });

  it('treats a trailing slash as directory-only but still matches by basename', () => {
    expect(isGitignored('config/local.yaml', ['config/'])).toBe(true);
  });

  it('honors ! negation applied after a matching pattern', () => {
    expect(isGitignored('config.yaml', ['*.yaml', '!config.yaml'])).toBe(false);
  });

  it('returns false for an empty pattern list', () => {
    expect(isGitignored('config.yaml', [])).toBe(false);
  });

  it('respects pattern order — a later match overrides an earlier one', () => {
    expect(isGitignored('config.yaml', ['!config.yaml', '*.yaml'])).toBe(true);
  });
});
