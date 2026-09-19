import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapInj002ToolOutputTrusted } from '../../src/checks/injection/chapInj002ToolOutputTrusted.js';
import { discoverAgent } from '../../src/discovery/index.js';

describe('CHAP-INJ-002 — tool output treated as trusted', () => {
  it('fires at high severity on the command-relay skill in the vulnerable fixture (a confirmed, traced chain)', () => {
    const { model } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'vulnerable-agent'),
    });

    const findings = chapInj002ToolOutputTrusted.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-INJ-002');
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.location.detail).toBe('command-relay');
    expect(findings[0]?.message).toContain('confirmed tool-output-to-shell-execution chain');
  });

  it('stays silent on the clean fixture (no skill combines ingestion with shell execution)', () => {
    const { model } = discoverAgent({ targetPath: path.join('test', 'fixtures', 'clean-agent') });

    expect(chapInj002ToolOutputTrusted.run(model)).toEqual([]);
  });

  // improvement_plan.md 1.16: a real data-flow improvement means severity
  // now distinguishes a confirmed chain (above) from a mere shape-match
  // (both capabilities present, nothing actually traced) — isolated here
  // since no existing named fixture happens to have both capabilities
  // without also having the real chain.
  describe('shape-match only (both capabilities present, nothing traced)', () => {
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-inj002-test-'));
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it('fires at the weaker medium severity when nothing is actually traced', () => {
      const skillDir = path.join(dir, 'skills', 'shape-only');
      mkdirSync(skillDir, { recursive: true });
      writeFileSync(
        path.join(skillDir, 'package.json'),
        JSON.stringify({ name: 'shape-only', version: '1.0.0' }),
      );
      writeFileSync(
        path.join(skillDir, 'index.js'),
        "const { exec } = require('child_process');\nasync function run(url) {\n  await fetch(url);\n  exec('ls');\n}\n",
      );
      writeFileSync(path.join(dir, 'config.yaml'), 'skills_dir: ./skills\n');

      const { model } = discoverAgent({ targetPath: dir });
      const findings = chapInj002ToolOutputTrusted.run(model);

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('medium');
      expect(findings[0]?.message).not.toContain('confirmed');
    });
  });
});
