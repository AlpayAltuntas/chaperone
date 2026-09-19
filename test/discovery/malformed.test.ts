import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { discoverAgent } from '../../src/discovery/index.js';

describe('discoverAgent — malformed and partial installs', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-malformed-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('records an unparseable config as skipped instead of throwing', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'gateway:\n  host: [unterminated\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(model.config.data).toBeNull();
    expect(
      model.skipped.some((s) => s.path.endsWith('config.yaml') && /unparseable/.test(s.reason)),
    ).toBe(true);
  });

  it('handles a missing skills directory without throwing', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  provider: anthropic\n');

    const { model } = discoverAgent({ targetPath: dir });

    expect(model.skills).toEqual([]);
  });

  it('skips a skill with an unparseable manifest but still returns the skill', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  provider: anthropic\n');
    const skillDir = path.join(dir, 'skills', 'broken');
    mkdirSync(skillDir, { recursive: true });
    writeFileSync(path.join(skillDir, 'package.json'), '{not valid json');

    const { model } = discoverAgent({ targetPath: dir });

    expect(model.skills).toHaveLength(1);
    expect(model.skills[0]?.name).toBe('broken'); // falls back to directory name
    expect(model.skipped.some((s) => /unparseable manifest/.test(s.reason))).toBe(true);
  });

  it('handles an install with no config file at all', () => {
    const { model } = discoverAgent({ targetPath: dir });

    expect(model.config.path).toBeNull();
    expect(model.config.data).toBeNull();
    expect(model.skipped.some((s) => /no config/.test(s.reason))).toBe(true);
  });

  // Regression test for improvement_plan.md 1.11: a skill manifest is
  // untrusted content (by definition, once CHAP-SUP-001 exists as a
  // check), and its name/author get printed directly by the console
  // reporter — a manifest embedding ANSI/control characters shouldn't be
  // able to manipulate the user's terminal.
  it('strips control characters (e.g. ANSI escapes) from a skill manifest name/author', () => {
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  provider: anthropic\n');
    const skillDir = path.join(dir, 'skills', 'hostile');
    mkdirSync(skillDir, { recursive: true });
    writeFileSync(
      path.join(skillDir, 'package.json'),
      JSON.stringify({ name: '\x1b[2Jhostile\x07', author: 'attacker\x1b[31m' }),
    );

    const { model } = discoverAgent({ targetPath: dir });

    expect(model.skills).toHaveLength(1);
    const skill = model.skills[0];
    expect(skill?.name).toBe('hostile');
    expect(skill?.provenance.author).toBe('attacker');
    // Belt and suspenders: no control character (0x00-0x1F, 0x7F) anywhere.
    // eslint-disable-next-line no-control-regex -- asserting control chars are absent
    expect(/[\x00-\x1F\x7F]/.test(skill?.name ?? '')).toBe(false);
  });
});
