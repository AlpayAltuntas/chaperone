import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { scanExistingLogContent } from '../../src/discovery/logContentScanner.js';

describe('scanExistingLogContent', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-logscan-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('finds a secret-shaped key/value pair in a JSON-ish log line', () => {
    const logPath = path.join(dir, 'agent.log');
    writeFileSync(
      logPath,
      '2026-01-01T00:00:00Z DEBUG request headers: {"api_key": "sk-real-looking-dummy-value"}\n',
    );

    const result = scanExistingLogContent(logPath);

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]?.keyName).toBe('api_key');
    expect(result.matches[0]?.displayValue).not.toContain('sk-real-looking-dummy-value');
  });

  it('finds a secret-shaped key/value pair in a plain key=value log line', () => {
    const logPath = path.join(dir, 'agent.log');
    writeFileSync(logPath, 'auth_token=abcdef0123456789 request completed\n');

    const result = scanExistingLogContent(logPath);

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]?.keyName).toBe('auth_token');
  });

  it('ignores non-secret-shaped keys', () => {
    const logPath = path.join(dir, 'agent.log');
    writeFileSync(logPath, 'request_id=8f14e45fceea167a status=ok\n');

    const result = scanExistingLogContent(logPath);

    expect(result.matches).toEqual([]);
  });

  it('returns nothing for an empty log file', () => {
    const logPath = path.join(dir, 'agent.log');
    writeFileSync(logPath, '');

    const result = scanExistingLogContent(logPath);

    expect(result.matches).toEqual([]);
    expect(result.skippedReason).toBeNull();
  });

  it('returns nothing (no throw) when the log file does not exist', () => {
    const result = scanExistingLogContent(path.join(dir, 'missing.log'));

    expect(result.matches).toEqual([]);
    expect(result.skippedReason).toBeNull();
  });

  it('caps the number of matches instead of scanning without bound', () => {
    const logPath = path.join(dir, 'agent.log');
    const lines = Array.from(
      { length: 30 },
      (_, i) => `api_key_${String(i)}=dummy-literal-value-${String(i)}`,
    );
    writeFileSync(logPath, lines.join('\n'));

    const result = scanExistingLogContent(logPath);

    expect(result.matches.length).toBeLessThanOrEqual(20);
  });

  it('scans only the tail and reports a skipped reason for an oversized log file', () => {
    const logPath = path.join(dir, 'agent.log');
    // Well past the 256 KiB scan cap.
    const padding = 'x'.repeat(300 * 1024);
    writeFileSync(logPath, `${padding}\napi_key=dummy-literal-value-at-the-end\n`);

    const result = scanExistingLogContent(logPath);

    expect(result.skippedReason).not.toBeNull();
    expect(result.skippedReason).toContain('only the last');
    expect(result.matches.some((m) => m.keyName === 'api_key')).toBe(true);
  });
});
