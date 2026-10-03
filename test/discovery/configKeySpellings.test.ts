import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parse } from 'yaml';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { configLine } from '../../src/checks/shared/configAccess.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { getConfigField } from '../../src/discovery/jsonUtils.js';
import { runChecks } from '../../src/engine/index.js';

const FIXTURE = path.join('test', 'fixtures', 'vulnerable-agent');

describe('getConfigField', () => {
  it.each([
    [{ auto_execute_links: true }, true],
    [{ autoExecuteLinks: true }, true],
    [{ 'auto-execute-links': true }, true],
    [{ AutoExecuteLinks: true }, true],
    [{ auto_execute: true }, undefined],
    [{ autoExecuteLinksExtra: true }, undefined],
  ])('reads %j as auto_execute_links -> %s', (record, expected) => {
    expect(getConfigField(record, 'auto_execute_links')).toBe(expected);
  });

  it('prefers the exact snake_case key when several spellings are present', () => {
    expect(
      getConfigField({ autoExecuteLinks: true, auto_execute_links: false }, 'auto_execute_links'),
    ).toBe(false);
  });
});

function toCamel(key: string): string {
  return key.replace(/[_-]([a-z0-9])/g, (_m, c: string) => c.toUpperCase());
}

function camelizeKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(camelizeKeys);
  }
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [toCamel(k), camelizeKeys(v)]));
  }
  return value;
}

function findingSignatures(targetPath: string): string[] {
  const { model } = discoverAgent({ targetPath });
  return runChecks(model, ALL_CHECKS)
    .findings.map((f) => `${f.checkId}:${f.severity}`)
    .sort();
}

// PROPOSED_FIXES.md 2.3: a camelCase JSON config (the norm for JSON) must
// produce exactly the findings its snake_case YAML equivalent does.
describe('config key spellings — camelCase JSON matches snake_case YAML', () => {
  let snakeDir: string;
  let camelDir: string;

  beforeEach(() => {
    const base = mkdtempSync(path.join(os.tmpdir(), 'chaperone-keyspell-'));
    snakeDir = path.join(base, 'snake');
    camelDir = path.join(base, 'camel');
    cpSync(FIXTURE, snakeDir, { recursive: true });
    cpSync(FIXTURE, camelDir, { recursive: true });
    const config = parse(readFileSync(path.join(FIXTURE, 'config.yaml'), 'utf8')) as unknown;
    rmSync(path.join(camelDir, 'config.yaml'));
    writeFileSync(
      path.join(camelDir, 'config.json'),
      JSON.stringify(camelizeKeys(config), null, 2),
      {
        mode: 0o644,
      },
    );
    // Same mode on both, so permission checks agree.
    writeFileSync(
      path.join(snakeDir, 'config.yaml'),
      readFileSync(path.join(FIXTURE, 'config.yaml')),
      { mode: 0o644 },
    );
  });

  afterEach(() => {
    rmSync(path.dirname(snakeDir), { recursive: true, force: true });
  });

  it('produces an identical finding set', () => {
    const camelConfig = readFileSync(path.join(camelDir, 'config.json'), 'utf8');
    expect(camelConfig).toContain('autoExecuteLinks');
    expect(camelConfig).toContain('skillsDir');

    const snake = findingSignatures(snakeDir);
    expect(snake).toContain('CHAP-INJ-004:high');
    expect(findingSignatures(camelDir)).toEqual(snake);
  });
});

// PROPOSED_FIXES.md 4.2: config findings point at the key's line.
describe('configLine', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-configline-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('finds a camelCase key in a JSON config, and falls back to the section for a missing key', () => {
    writeFileSync(
      path.join(dir, 'config.json'),
      JSON.stringify({ trust: { autoExecuteLinks: true } }, null, 2),
    );
    const { model } = discoverAgent({ targetPath: dir });

    expect(configLine(model, ['trust', 'auto_execute_links'])).toBe(3);
    expect(configLine(model, ['trust', 'tool_allowlist'])).toBe(2);
    expect(configLine(model, ['gateway', 'host'])).toBeNull();
  });
});
