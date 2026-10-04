import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapSec008WritableByOthers } from '../../src/checks/secrets/chapSec008WritableByOthers.js';
import { discoverAgent } from '../../src/discovery/index.js';

// Modes are set with chmod at test time, not committed: git doesn't
// preserve them, and umask varies between machines.
describe.skipIf(process.platform === 'win32')(
  'CHAP-SEC-008 — agent files writable by others',
  () => {
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-sec008-test-'));
      chmodSync(dir, 0o755);
      writeFileSync(path.join(dir, 'config.yaml'), 'memory_dir: ./memory\n', { mode: 0o600 });
      mkdirSync(path.join(dir, 'skills', 'helper'), { recursive: true });
      mkdirSync(path.join(dir, 'memory'));
      chmodSync(path.join(dir, 'skills'), 0o755);
      chmodSync(path.join(dir, 'skills', 'helper'), 0o755);
      chmodSync(path.join(dir, 'memory'), 0o700);
      writeFileSync(path.join(dir, 'skills', 'helper', 'package.json'), '{"name":"helper"}');
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    function run(): ReturnType<typeof chapSec008WritableByOthers.run> {
      const { model } = discoverAgent({ targetPath: dir });
      return chapSec008WritableByOthers.run(model);
    }

    it('stays silent when nothing is group/other-writable', () => {
      expect(run()).toEqual([]);
    });

    // PROPOSED_FIXES.md Appendix A.11.
    it('flags a world-writable skills directory', () => {
      chmodSync(path.join(dir, 'skills'), 0o777);

      const findings = run();

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ checkId: 'CHAP-SEC-008', severity: 'high' });
      expect(findings[0]?.message).toContain(
        'skills directory is writable by group or other (mode 777)',
      );
      expect(findings[0]?.message).toContain('plant a new skill');
      expect(findings[0]?.remediation).toContain('chmod -R go-w');
    });

    it.each([
      ['a group-writable skill directory', ['skills', 'helper'], 0o775, 'skill directory'],
      ['a world-writable memory directory', ['memory'], 0o777, 'memory directory'],
      ['a group-writable install directory', [], 0o775, 'install directory'],
      ['a group-writable config file', ['config.yaml'], 0o620, 'config file'],
    ])('flags %s', (_label, segments, mode, expectedLabel) => {
      chmodSync(path.join(dir, ...segments), mode);

      const findings = run();

      expect(findings).toHaveLength(1);
      expect(findings[0]?.message).toContain(`The ${expectedLabel} is writable`);
    });

    it('ignores a group-readable (not writable) config file — that is CHAP-SEC-003', () => {
      chmodSync(path.join(dir, 'config.yaml'), 0o644);

      expect(run()).toEqual([]);
    });
  },
);
