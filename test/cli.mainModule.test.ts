import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { isMainModule } from '../src/cli.js';

// Regression test for a real bug caught by installing a packed npm
// tarball before publishing (see DECISIONS.md): npm's node_modules/.bin/
// entries are symlinks. process.argv[1] is the literal symlink path Node
// was invoked with; import.meta.url resolves through the symlink to the
// real file. A naive `=== file://${argv[1]}` comparison never matched
// once installed for real, so `chaperone` silently did nothing — no
// output, exit 0. Caught only by actually installing the package, since
// every other test here calls run() directly and never exercises this
// entrypoint-detection path at all.
// Node's ESM loader always resolves import.meta.url through the real
// path (e.g. macOS's /tmp -> /private/tmp symlink), so tests must build
// their "moduleUrl" the same way rather than from the raw temp-dir path —
// otherwise they'd fail for the same class of reason the bug itself did.
function moduleUrlFor(realFile: string): string {
  return pathToFileURL(realpathSync(realFile)).href;
}

describe('isMainModule', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-mainmodule-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('matches when the module URL is the real file and argv[1] is a symlink to it (the npm bin case)', () => {
    const realFile = path.join(dir, 'real', 'cli.js');
    mkdirSync(path.dirname(realFile), { recursive: true });
    writeFileSync(realFile, '// stub\n');
    const symlinkPath = path.join(dir, 'bin-link.js');
    symlinkSync(realFile, symlinkPath);

    expect(isMainModule(symlinkPath, moduleUrlFor(realFile))).toBe(true);
  });

  it('matches when argv[1] is the real file directly (running `node dist/cli.js`)', () => {
    const realFile = path.join(dir, 'cli.js');
    writeFileSync(realFile, '// stub\n');

    expect(isMainModule(realFile, moduleUrlFor(realFile))).toBe(true);
  });

  it('does not match when the module was imported from an unrelated entry point (the test-runner case)', () => {
    const realFile = path.join(dir, 'cli.js');
    const otherEntry = path.join(dir, 'vitest-worker.js');
    writeFileSync(realFile, '// stub\n');
    writeFileSync(otherEntry, '// stub\n');

    expect(isMainModule(otherEntry, moduleUrlFor(realFile))).toBe(false);
  });

  it('returns false rather than throwing when argv[1] is undefined', () => {
    expect(isMainModule(undefined, 'file:///anything')).toBe(false);
  });

  it('returns false rather than throwing when argv[1] points to a nonexistent file', () => {
    expect(isMainModule(path.join(dir, 'does-not-exist.js'), 'file:///anything')).toBe(false);
  });
});
