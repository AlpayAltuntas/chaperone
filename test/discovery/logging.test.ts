import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { extractLoggingModel } from '../../src/discovery/logging.js';

describe('extractLoggingModel', () => {
  it('resolves a relative log path against the target root', () => {
    const model = extractLoggingModel({ logging: { path: './logs/agent.log' } }, '/fake/target');

    expect(model.path).toBe(path.resolve('/fake/target', 'logs', 'agent.log'));
  });

  // Regression test for improvement_plan.md 1.4.
  it('expands a ~/ log path to the real home directory instead of a literal "~" subdirectory', () => {
    const model = extractLoggingModel({ logging: { path: '~/logs/agent.log' } }, '/fake/target');

    expect(model.path).toBe(path.join(os.homedir(), 'logs', 'agent.log'));
    expect(model.path).not.toContain('/fake/target');
    expect(model.path?.includes('~')).toBe(false);
  });

  it('returns present: false when there is no logging section', () => {
    expect(extractLoggingModel({}, '/fake/target').present).toBe(false);
  });
});
