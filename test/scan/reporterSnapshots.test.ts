import { chmodSync, cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { runChecks } from '../../src/engine/index.js';
import { REPORT_FORMATS, renderReport } from '../../src/reporters/index.js';
import type { ScanMetadata } from '../../src/reporters/types.js';

// improvement_plan.md 5.1 — golden-file/snapshot testing of full
// reporter output. The existing reporter tests (test/reporters/*.test.ts)
// assert specific substrings/counts against small, hand-built finding
// arrays; this instead snapshots the COMPLETE, real output of every
// format against both real fixtures, run through the real
// discover -> check -> render pipeline — the kind of accidental
// whitespace/ordering/field regression a substring assertion can miss
// entirely. First run creates test/scan/__snapshots__/
// reporterSnapshots.test.ts.snap; `vitest run -u` updates it
// deliberately, same as any vitest snapshot.
//
// Two things vary between machines/CI runs and must be normalized
// before snapshotting, or every run would produce a "new" snapshot:
// the scan timestamp, and the temp directory's absolute path (a fresh
// mkdtempSync path every run, and a different filesystem root on CI
// than locally) — replaced with fixed placeholders below.

function copyFixtureWithPermissions(name: string, mode: number): string {
  const src = path.join('test', 'fixtures', name);
  const dest = mkdtempSync(path.join(os.tmpdir(), `chaperone-snapshot-${name}-`));
  cpSync(src, dest, { recursive: true });
  mkdirSync(path.join(dest, '.git'));
  writeFileSync(path.join(dest, '.gitignore'), 'node_modules/\ndist/\n');
  chmodSync(path.join(dest, 'config.yaml'), mode);
  chmodSync(path.join(dest, 'logs', 'agent.log'), mode);
  return dest;
}

function normalize(text: string, targetRoot: string): string {
  return (
    text
      .replaceAll(targetRoot, '<TARGET_ROOT>')
      // CHAP-SUP-004's finding location is a relative-looking
      // "package.json#scripts.<name>" string (not resolved against the
      // scanned target the way every other check's location is) —
      // formatSarifReport's pathToFileURL() resolves that relative path
      // against the *test process's own* cwd (the repo checkout root),
      // which differs between machines/CI just as much as a temp dir
      // does, so it needs the same normalization.
      .replaceAll(pathToFileURL(process.cwd()).href, '<REPO_ROOT_URL>')
      .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/g, '<TIMESTAMP>')
  );
}

describe('reporter output — golden-file snapshots (improvement_plan.md 5.1)', () => {
  describe('vulnerable-agent', () => {
    let dir: string;

    beforeEach(() => {
      dir = copyFixtureWithPermissions('vulnerable-agent', 0o644);
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it.each(REPORT_FORMATS)('matches the golden %s output', (format) => {
      const { model, targetRootResolved } = discoverAgent({ targetPath: dir });
      const { findings } = runChecks(model, ALL_CHECKS);
      const metadata: ScanMetadata = {
        target: model.targetRoot,
        targetRootResolved,
        timestamp: '2026-01-01T00:00:00.000Z',
        toolVersion: '0.1.0',
        inspected: model.inspected,
        skipped: model.skipped,
      };

      const report = renderReport(format, findings, metadata, { console: { color: false } });

      expect(normalize(report, dir)).toMatchSnapshot();
    });
  });

  describe('clean-agent', () => {
    let dir: string;

    beforeEach(() => {
      vi.stubEnv('ANTHROPIC_API_KEY', 'test-value');
      vi.stubEnv('TELEGRAM_BOT_TOKEN', 'test-value');
      vi.stubEnv('GATEWAY_AUTH_TOKEN', 'test-value');
      dir = copyFixtureWithPermissions('clean-agent', 0o600);
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
      vi.unstubAllEnvs();
    });

    it.each(REPORT_FORMATS)('matches the golden %s output', (format) => {
      const { model, targetRootResolved } = discoverAgent({ targetPath: dir });
      const { findings } = runChecks(model, ALL_CHECKS);
      const metadata: ScanMetadata = {
        target: model.targetRoot,
        targetRootResolved,
        timestamp: '2026-01-01T00:00:00.000Z',
        toolVersion: '0.1.0',
        inspected: model.inspected,
        skipped: model.skipped,
      };

      const report = renderReport(format, findings, metadata, { console: { color: false } });

      expect(normalize(report, dir)).toMatchSnapshot();
    });
  });
});
