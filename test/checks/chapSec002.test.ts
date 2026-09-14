import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSec002GitTrackedSecrets } from '../../src/checks/secrets/chapSec002GitTrackedSecrets.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-SEC-002 — secrets in a git-tracked path', () => {
  it('fires on the vulnerable fixture (a real literal secret, git-tracked, not gitignored)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapSec002GitTrackedSecrets.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-SEC-002');
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.location.filePath).toBe(model.config.path);
  });

  it('stays silent on the clean fixture (no literal secret to protect)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapSec002GitTrackedSecrets.run(model)).toEqual([]);
  });

  describe('gitignore/no-git edge cases (isolated temp repos)', () => {
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sec002-test-'));
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it('stays silent when the config is covered by the repo .gitignore', () => {
      mkdirSync(path.join(dir, '.git'));
      writeFileSync(path.join(dir, '.gitignore'), 'config.yaml\n');
      writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  api_key: sk-ant-abcdefghijklmnop\n');

      const { model } = discoverAgent({ targetPath: dir });

      expect(chapSec002GitTrackedSecrets.run(model)).toEqual([]);
    });

    it('stays silent when there is no ancestor .git at all', () => {
      writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  api_key: sk-ant-abcdefghijklmnop\n');

      const { model } = discoverAgent({ targetPath: dir });

      expect(chapSec002GitTrackedSecrets.run(model)).toEqual([]);
    });

    it('fires when git-tracked, not gitignored, and holding a literal secret', () => {
      mkdirSync(path.join(dir, '.git'));
      writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n');
      writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  api_key: sk-ant-abcdefghijklmnop\n');

      const { model } = discoverAgent({ targetPath: dir });

      expect(chapSec002GitTrackedSecrets.run(model)).toHaveLength(1);
    });
  });
});
