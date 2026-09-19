import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { extractMemoryModel } from '../../src/discovery/memory.js';

describe('extractMemoryModel', () => {
  it('resolves a relative memory_dir against the target root', () => {
    const model = extractMemoryModel({ memory_dir: './memory' }, '/fake/target');

    expect(model.present).toBe(true);
    expect(model.dir).toBe(path.resolve('/fake/target', 'memory'));
  });

  it('falls back to state_dir when memory_dir is absent', () => {
    const model = extractMemoryModel({ state_dir: './state' }, '/fake/target');

    expect(model.present).toBe(true);
    expect(model.dir).toBe(path.resolve('/fake/target', 'state'));
  });

  it('prefers memory_dir when both memory_dir and state_dir are set', () => {
    const model = extractMemoryModel(
      { memory_dir: './memory', state_dir: './state' },
      '/fake/target',
    );

    expect(model.dir).toBe(path.resolve('/fake/target', 'memory'));
  });

  it('expands a ~/ memory_dir to the real home directory, mirroring expandHome elsewhere', () => {
    const model = extractMemoryModel({ memory_dir: '~/agent-memory' }, '/fake/target');

    expect(model.dir).toBe(path.join(os.homedir(), 'agent-memory'));
  });

  it('returns present: false when neither field is configured', () => {
    expect(extractMemoryModel({}, '/fake/target')).toEqual({ present: false, dir: null });
  });

  it('returns present: false for a non-record config', () => {
    expect(extractMemoryModel(null, '/fake/target')).toEqual({ present: false, dir: null });
  });
});
