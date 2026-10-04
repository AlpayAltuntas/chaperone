import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { detectCapabilities } from '../../src/discovery/astCapabilities.js';

// PROPOSED_FIXES.md 3.2: APIs and indirection forms the AST pass used to miss.
// Each capability has positives and at least one negative.

describe('shell execution — additional APIs', () => {
  it.each([
    ['child_process.fork', "const cp = require('child_process'); cp.fork(p);"],
    ['execa named', "const { execa } = require('execa'); await execa('sh', ['-c', cmd]);"],
    ['execa default', "import execa from 'execa'; execa(cmd);"],
    ['execa $ tagged template', "import { $ } from 'execa'; await $`ls ${dir}`;"],
    ['shelljs', "const shell = require('shelljs'); shell.exec(cmd);"],
    ['zx $', "import { $ } from 'zx'; await $`rm -rf ${dir}`;"],
    ['cross-spawn', "const spawn = require('cross-spawn'); spawn(cmd, args);"],
    ['node-pty', "import * as pty from 'node-pty'; pty.spawn('bash', []);"],
    ['Bun.spawn', "Bun.spawn(['sh', '-c', cmd]);"],
    ['Deno.Command', "new Deno.Command('sh', { args: ['-c', cmd] }).spawn();"],
    [
      'one-level alias of element access',
      "const cp = require('child_process'); const run = cp['exec']; run(c);",
    ],
    [
      'alias of property access',
      "const cp = require('node:child_process'); const run = cp.execSync; run(c);",
    ],
    ['template-literal key', "const cp = require('child_process'); cp[`exec`](c);"],
    ['inline require', "require('child_process').execSync(c);"],
    [
      'alias of alias',
      "const cp = require('child_process'); const a = cp.exec; const b = a; b(c);",
    ],
  ])('detects %s', (_label, source) => {
    expect(detectCapabilities('index.mjs', source).shellExec).toBe(true);
  });

  it.each([
    ['a local function named exec', 'function exec(x) { return x; } exec(c);'],
    ['a regex exec', '/a+/.exec(text);'],
    ['shelljs non-exec API', "const shell = require('shelljs'); shell.echo('hi');"],
    ['a locally bound Bun', 'const Bun = { spawn() {} }; Bun.spawn([]);'],
    ['a computed key', "const cp = require('child_process'); cp[name](c);"],
  ])('ignores %s', (_label, source) => {
    expect(detectCapabilities('index.mjs', source).shellExec).toBe(false);
  });
});

describe('filesystem writes — additional APIs', () => {
  it.each([
    ['fs.promises.writeFile', "const fs = require('fs'); fs.promises.writeFile(p, 'x');"],
    ['require(fs).promises alias', "const fsp = require('fs').promises; fsp.writeFile(p, 'x');"],
    ['destructured promises', "const { promises } = require('fs'); promises.rm(p);"],
    ['rename', "import fs from 'node:fs'; fs.renameSync(a, b);"],
    ['createWriteStream', "import { createWriteStream } from 'fs'; createWriteStream(p);"],
    ['fs-extra outputFile', "const fse = require('fs-extra'); fse.outputFile(p, d);"],
    ['fs-extra remove', "import { remove } from 'fs-extra'; await remove(p);"],
    ['rimraf', "const { rimraf } = require('rimraf'); rimraf(p);"],
    ['del', "import { deleteAsync } from 'del'; await deleteAsync([p]);"],
  ])('detects %s', (_label, source) => {
    expect(detectCapabilities('index.mjs', source).fileSystemAccess).toBe(true);
  });

  it.each([
    ['fs reads only', "const fs = require('fs'); fs.readFileSync(p); fs.promises.readFile(p);"],
    ['a local rename', 'function rename(a, b) {} rename(x, y);'],
  ])('ignores %s', (_label, source) => {
    expect(detectCapabilities('index.mjs', source).fileSystemAccess).toBe(false);
  });
});

describe('network — additional APIs', () => {
  it.each([
    ['undici', "import { request } from 'undici'; await request(url);"],
    ['got', "import got from 'got'; await got(url);"],
    ['ky', "import ky from 'ky'; await ky.get(url);"],
    ['superagent', "const sa = require('superagent'); sa.get(url);"],
    ['ws constructor', "const WebSocket = require('ws'); new WebSocket(url);"],
    ['net', "import net from 'node:net'; net.connect(80, host);"],
    ['dgram', "const dgram = require('dgram'); dgram.createSocket('udp4');"],
    ['global WebSocket', 'new WebSocket(url);'],
    ['global XMLHttpRequest', 'const x = new XMLHttpRequest();'],
    ['global EventSource', 'new EventSource(url);'],
    ['globalThis.fetch', 'globalThis.fetch(url);'],
    ['a same-name alias of the global', 'const fetch = globalThis.fetch; fetch(url);'],
  ])('detects %s', (_label, source) => {
    expect(detectCapabilities('index.mjs', source).networkAccess).toBe(true);
  });

  it('ignores a locally declared fetch', () => {
    const source = 'function fetch(u) { return cache[u]; } fetch(url);';
    expect(detectCapabilities('index.mjs', source).networkAccess).toBe(false);
  });

  it('ignores a locally defined WebSocket class', () => {
    const source = "import WebSocket from './myws.js'; new WebSocket(url);";
    expect(detectCapabilities('index.mjs', source).networkAccess).toBe(false);
  });
});

describe('dynamic code — additional forms', () => {
  it.each([
    ['indirect (0, eval)', '(0, eval)(c);'],
    ['globalThis.eval', 'globalThis.eval(c);'],
    ['window.eval', 'window.eval(c);'],
    ['global.eval', 'global.eval(c);'],
    ["self['eval']", "self['eval'](c);"],
    ['new globalThis.Function', "new globalThis.Function('return 1')();"],
    ['an alias of eval', 'const e = eval; e(c);'],
    ['vm.runInNewContext', "const vm = require('vm'); vm.runInNewContext(code);"],
    ['new vm.Script', "import vm from 'node:vm'; new vm.Script(code);"],
    ['vm named import', "import { runInThisContext } from 'vm'; runInThisContext(code);"],
    ['dynamic require', 'require(cmd);'],
    ['dynamic import', 'await import(name);'],
    ['setTimeout with a string', "setTimeout('doEvil()', 10);"],
    ['setInterval with a template', 'setInterval(`run(${x})`, 10);'],
    ['module._compile', 'module._compile(src, file);'],
  ])('detects %s', (_label, source) => {
    expect(detectCapabilities('index.js', source).dynamicEval).toBe(true);
  });

  it.each([
    ['a literal require', "require('./lib.js');"],
    ['a literal dynamic import', "await import('./lib.js');"],
    ['setTimeout with a function', 'setTimeout(() => run(), 10);'],
    ['a method named eval on a local object', 'const calc = { eval() {} }; calc.eval(x);'],
    ['vm non-eval API', "const vm = require('vm'); vm.isContext(ctx);"],
  ])('ignores %s', (_label, source) => {
    expect(detectCapabilities('index.js', source).dynamicEval).toBe(false);
  });
});

// The two probe skills from PROPOSED_FIXES.md Appendix A.9, which used to
// produce zero agency/obfuscation findings.
describe('Appendix A.9 probe skills', () => {
  it('detects everything in skills/sneaky/index.js', () => {
    const caps = detectCapabilities(
      'index.js',
      `const { execa } = require('execa');
const shell = require('shelljs');
const fs = require('fs');
const vm = require('vm');
module.exports = async (cmd, p, code) => {
  await execa('sh', ['-c', cmd]);
  shell.exec(cmd);
  fs.promises.writeFile(p, 'x');
  vm.runInNewContext(code);
  require(cmd);
};`,
    );
    expect(caps).toMatchObject({ shellExec: true, fileSystemAccess: true, dynamicEval: true });
  });

  it('detects everything in skills/evil2/index.js', () => {
    const caps = detectCapabilities(
      'index.js',
      `const cp = require('child_process');
const run = cp['exec'];
module.exports = (c) => {
  run(c);
  (0, eval)(c);
  globalThis.eval(c);
};`,
    );
    expect(caps).toMatchObject({ shellExec: true, dynamicEval: true });
  });
});

describe('detectCapabilities — robustness', () => {
  it('never throws on arbitrary source', () => {
    fc.assert(
      fc.property(fc.string(), (source) => {
        expect(() => detectCapabilities('index.js', source)).not.toThrow();
      }),
    );
  });

  it('never throws on arbitrary source built from JS tokens', () => {
    const token = fc.constantFrom(
      'require(',
      "'child_process'",
      ')',
      '(',
      '.exec',
      '[',
      ']',
      '`',
      '${',
      '}',
      'const ',
      'x',
      ' = ',
      ';',
      'eval',
      '(0, ',
      'new ',
      'import(',
      'globalThis.',
      'Deno.',
      'Bun.',
    );
    fc.assert(
      fc.property(fc.array(token, { maxLength: 40 }), (tokens) => {
        expect(() => detectCapabilities('index.ts', tokens.join(''))).not.toThrow();
      }),
    );
  });
});

describe('per-call scoping — path expression forms (PROPOSED_FIXES.md 2.6)', () => {
  it.each([
    [
      'a template literal rooted at __dirname',
      "const fs = require('fs');\nfs.writeFileSync(`${__dirname}/out/${name}`, d);",
    ],
    [
      'string concatenation rooted at __dirname',
      "const fs = require('fs');\nfs.writeFileSync(__dirname + '/out/' + name, d);",
    ],
    [
      'an array of scoped paths to del',
      "import { deleteAsync } from 'del';\nimport path from 'node:path';\nawait deleteAsync([path.join(__dirname, 'tmp')]);",
    ],
    [
      'new URL relative to import.meta.url',
      "import { writeFile } from 'node:fs/promises';\nawait writeFile(new URL('./out.json', import.meta.url), d);",
    ],
    [
      'an awaited scoped path',
      "const fs = require('fs');\nconst path = require('path');\nfs.writeFileSync(await path.join(__dirname, 'a'), d);",
    ],
  ])('treats %s as scoped', (_label, source) => {
    const result = detectCapabilities('index.mjs', source);
    expect(result.fileSystemAccess).toBe(true);
    expect(result.fileSystemScoped).toBe(true);
  });

  it.each([
    [
      'a template literal with a leading variable',
      "const fs = require('fs');\nfs.writeFileSync(`${userDir}/out`, d);",
    ],
    [
      'a template literal with fixed text before the variable',
      "const fs = require('fs');\nfs.writeFileSync(`/${name}`, d);",
    ],
    ['an empty array to del', "import { deleteAsync } from 'del';\nawait deleteAsync([]);"],
    ['the filesystem root', "const fs = require('fs');\nfs.rmSync('/', { recursive: true });"],
    [
      'a home-directory literal',
      "const fs = require('fs');\nfs.rmSync('~/', { recursive: true });",
    ],
  ])('treats %s as unscoped', (_label, source) => {
    expect(detectCapabilities('index.mjs', source).fileSystemScoped).toBe(false);
  });
});

describe('detectCapabilities — parsing variants', () => {
  it('parses .jsx files with JSX syntax', () => {
    const source =
      "import { exec } from 'child_process';\nexport const A = () => <b onClick={() => exec(c)} />;";
    expect(detectCapabilities('Widget.jsx', source).shellExec).toBe(true);
  });

  it('resolves `import { default as x }` to the module itself', () => {
    expect(
      detectCapabilities('a.mjs', "import { default as got } from 'got';\ngot(url);").networkAccess,
    ).toBe(true);
  });

  it('traces taint through a template literal into exec', () => {
    const source =
      "const { exec } = require('child_process');\nasync function f(u) {\n  const r = await fetch(u);\n  const body = await r.text();\n  exec(`sh -c ${body}`);\n}";
    expect(detectCapabilities('a.js', source).dataFlowToShellExec).toBe(true);
  });
});
