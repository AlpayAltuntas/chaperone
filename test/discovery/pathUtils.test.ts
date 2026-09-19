import { describe, expect, it } from 'vitest';
import { expandHome } from '../../src/discovery/pathUtils.js';

// Regression tests for improvement_plan.md 1.4: `path.resolve` has no
// concept of `~`, so a config value like `~/logs/agent.log` was silently
// resolved as a literal "~" subdirectory rather than the home directory.
describe('expandHome', () => {
  it('expands a bare ~ to the home directory', () => {
    expect(expandHome('~', '/fake/home')).toBe('/fake/home');
  });

  it('expands a ~/ prefix to the home directory', () => {
    expect(expandHome('~/logs/agent.log', '/fake/home')).toBe('/fake/home/logs/agent.log');
  });

  it('leaves an absolute path untouched', () => {
    expect(expandHome('/var/log/agent.log', '/fake/home')).toBe('/var/log/agent.log');
  });

  it('leaves a relative path untouched', () => {
    expect(expandHome('./logs/agent.log', '/fake/home')).toBe('./logs/agent.log');
  });

  it('does not expand ~otheruser (unsupported, left as-is)', () => {
    expect(expandHome('~otheruser/logs', '/fake/home')).toBe('~otheruser/logs');
  });

  it('defaults to the real os.homedir() when no homeDir is passed', () => {
    const result = expandHome('~/logs');
    expect(result).not.toContain('~');
    expect(result.endsWith('logs')).toBe(true);
  });
});
