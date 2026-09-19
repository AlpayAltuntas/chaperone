import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import YAML from 'yaml';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSec001Fixer } from '../../src/fix/chapSec001Fixer.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('chapSec001Fixer', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-fixer-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('replaces every literal secret with a ${VAR} reference, preserving YAML formatting/comments', () => {
    const configPath = path.join(dir, 'config.yaml');
    writeFileSync(
      configPath,
      [
        '# a comment that must survive',
        'llm:',
        '  provider: anthropic',
        '  api_key: sk-ant-real-secret-value-shhh',
        'gateway:',
        '  host: 127.0.0.1',
        '',
      ].join('\n'),
    );

    const { model } = discoverAgent({ targetPath: dir });
    const plan = chapSec001Fixer.plan(model);

    if (plan === null) {
      throw new Error('expected a fix plan');
    }
    expect(plan.filePath).toBe(configPath);
    expect(plan.changes).toHaveLength(1);
    expect(plan.changes[0]?.keyPath).toBe('llm.api_key');
    expect(plan.changes[0]?.newValue).toBe('${LLM_API_KEY}');
    expect(typeof plan.changes[0]?.oldDisplayValue).toBe('string');
    expect(plan.newContent).toContain('# a comment that must survive');
    expect(plan.newContent).toContain('provider: anthropic');
    expect(plan.newContent).toContain('api_key: ${LLM_API_KEY}');
    expect(plan.newContent).not.toContain('sk-ant-real-secret-value-shhh');

    // plan() never writes — the original file on disk is untouched.
    expect(readFileSync(configPath, 'utf8')).not.toContain('${LLM_API_KEY}');
  });

  it('the proposed newContent parses as valid YAML with the field actually replaced', () => {
    const configPath = path.join(dir, 'config.yaml');
    writeFileSync(configPath, 'llm:\n  api_key: sk-real-secret-value\n');

    const { model } = discoverAgent({ targetPath: dir });
    const plan = chapSec001Fixer.plan(model);
    if (plan === null) {
      throw new Error('expected a fix plan');
    }

    const parsed = YAML.parse(plan.newContent) as { llm: { api_key: string } };
    expect(parsed.llm.api_key).toBe('${LLM_API_KEY}');
  });

  it('supports a JSON config, round-tripping without the literal secret', () => {
    const configPath = path.join(dir, 'config.json');
    writeFileSync(
      configPath,
      JSON.stringify({ llm: { api_key: 'sk-real-secret-value' } }, null, 2),
    );

    const { model } = discoverAgent({ targetPath: dir });
    const plan = chapSec001Fixer.plan(model);
    if (plan === null) {
      throw new Error('expected a fix plan');
    }

    const parsed = JSON.parse(plan.newContent) as { llm: { api_key: string } };
    expect(parsed.llm.api_key).toBe('${LLM_API_KEY}');
    expect(plan.newContent).not.toContain('sk-real-secret-value');
  });

  it('returns null when there is no config file at all', () => {
    const { model } = discoverAgent({ targetPath: dir });
    expect(chapSec001Fixer.plan(model)).toBeNull();
  });

  it('returns null when every secret-shaped value is already an env-var reference', () => {
    const configPath = path.join(dir, 'config.yaml');
    writeFileSync(configPath, 'llm:\n  api_key: ${LLM_API_KEY}\n');

    const { model } = discoverAgent({ targetPath: dir });
    expect(chapSec001Fixer.plan(model)).toBeNull();
  });

  it('proposes a distinct env-var name per field when there are multiple literal secrets', () => {
    const configPath = path.join(dir, 'config.yaml');
    writeFileSync(
      configPath,
      ['llm:', '  api_key: sk-one', 'channels:', '  telegram:', '    bot_token: tg-two', ''].join(
        '\n',
      ),
    );

    const { model } = discoverAgent({ targetPath: dir });
    const plan = chapSec001Fixer.plan(model);
    if (plan === null) {
      throw new Error('expected a fix plan');
    }

    const newValues = plan.changes.map((c) => c.newValue).sort();
    expect(newValues).toEqual(['${CHANNELS_TELEGRAM_BOT_TOKEN}', '${LLM_API_KEY}']);
  });
});
