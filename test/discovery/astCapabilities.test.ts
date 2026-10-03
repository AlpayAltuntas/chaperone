import { describe, expect, it } from 'vitest';
import { detectCapabilities, mergeCapabilities } from '../../src/discovery/astCapabilities.js';

describe('detectCapabilities — shellExec', () => {
  it('detects a named require destructure call (const { exec } = require(...); exec(x))', () => {
    const result = detectCapabilities(
      'skill.js',
      "const { exec } = require('child_process');\nexec('ls');\n",
    );
    expect(result.shellExec).toBe(true);
  });

  it('detects a namespace require property call (const cp = require(...); cp.execSync(x))', () => {
    const result = detectCapabilities(
      'skill.js',
      "const cp = require('child_process');\ncp.execSync('ls');\n",
    );
    expect(result.shellExec).toBe(true);
  });

  it('detects an ESM named import call', () => {
    const result = detectCapabilities(
      'skill.js',
      "import { spawn } from 'child_process';\nspawn('ls');\n",
    );
    expect(result.shellExec).toBe(true);
  });

  it('detects an ESM namespace import property call', () => {
    const result = detectCapabilities(
      'skill.js',
      "import * as cp from 'child_process';\ncp.spawnSync('ls');\n",
    );
    expect(result.shellExec).toBe(true);
  });

  it('resolves an aliased named import back to the real exported function', () => {
    const result = detectCapabilities(
      'skill.js',
      "import { exec as run } from 'child_process';\nrun('ls');\n",
    );
    expect(result.shellExec).toBe(true);
  });

  it('detects dynamic string-literal element access (child_process["exec"])', () => {
    const result = detectCapabilities(
      'skill.js',
      "const cp = require('child_process');\ncp['exec']('ls');\n",
    );
    expect(result.shellExec).toBe(true);
  });

  it('does not fire when "exec" only appears in a comment (fixes the old regex false positive)', () => {
    const result = detectCapabilities('skill.js', "// this skill could exec('ls') in theory\n");
    expect(result.shellExec).toBe(false);
  });

  it('does not fire when "exec" only appears in a string literal', () => {
    const result = detectCapabilities('skill.js', "const log = 'about to exec(\\'ls\\')';\n");
    expect(result.shellExec).toBe(false);
  });

  it('does not fire for an unrelated function named exec with no child_process binding', () => {
    const result = detectCapabilities('skill.js', 'function exec(x) { return x; }\nexec(1);\n');
    expect(result.shellExec).toBe(false);
  });
});

describe('detectCapabilities — fileSystemAccess / fileSystemScoped', () => {
  it('detects fs.writeFileSync via a namespace require', () => {
    const result = detectCapabilities(
      'skill.js',
      "const fs = require('fs');\nfs.writeFileSync('/tmp/x', 'y');\n",
    );
    expect(result.fileSystemAccess).toBe(true);
  });

  it('detects fs.unlink via an ESM namespace import', () => {
    const result = detectCapabilities(
      'skill.ts',
      "import * as fs from 'fs';\nfs.unlink('/tmp/x', () => {});\n",
    );
    expect(result.fileSystemAccess).toBe(true);
  });

  it('detects scoping via path.join(__dirname, ...)', () => {
    const result = detectCapabilities(
      'skill.js',
      "const path = require('path');\nconst dir = path.join(__dirname, 'workspace');\n",
    );
    expect(result.fileSystemScoped).toBe(true);
  });

  // PROPOSED_FIXES.md 2.6 — ESM modules have no __dirname; these are the
  // idiomatic replacements, and each used to be flagged as unscoped.
  it.each([
    [
      'import.meta.dirname',
      "import path from 'node:path';\nconst dir = path.join(import.meta.dirname, 'out');\n",
    ],
    [
      'path.resolve(import.meta.dirname, ...)',
      "import path from 'node:path';\nconst dir = path.resolve(import.meta.dirname, 'out');\n",
    ],
    [
      'an inline dirname(fileURLToPath(import.meta.url))',
      "import path from 'node:path';\nimport { fileURLToPath } from 'node:url';\nconst dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'out');\n",
    ],
    [
      'a variable derived from import.meta.url',
      "import path from 'node:path';\nimport { fileURLToPath } from 'node:url';\nconst here = path.dirname(fileURLToPath(import.meta.url));\nconst dir = path.join(here, 'out');\n",
    ],
    [
      'a hand-rolled __dirname shim',
      "import path from 'node:path';\nimport { fileURLToPath } from 'node:url';\nconst __dirname = path.dirname(fileURLToPath(import.meta.url));\nconst dir = path.join(__dirname, 'out');\n",
    ],
  ])('detects ESM scoping via %s', (_label, code) => {
    const result = detectCapabilities('skill.mjs', code);
    expect(result.fileSystemScoped).toBe(true);
  });

  it('does not treat path.join on a variable unrelated to the module location as scoping', () => {
    const result = detectCapabilities(
      'skill.mjs',
      "import path from 'node:path';\nconst base = process.argv[2];\nconst dir = path.join(base, 'out');\n",
    );
    expect(result.fileSystemScoped).toBe(false);
  });

  it('does not treat path.join without __dirname as scoping', () => {
    const result = detectCapabilities(
      'skill.js',
      "const path = require('path');\nconst dir = path.join('/tmp', 'workspace');\n",
    );
    expect(result.fileSystemScoped).toBe(false);
  });

  it('detects scoping via a WORKSPACE-named variable', () => {
    const result = detectCapabilities('skill.js', "const WORKSPACE = '/tmp/sandboxed';\n");
    expect(result.fileSystemScoped).toBe(true);
  });

  it('does not fire fileSystemAccess for an unrelated writeFileSync with no fs binding', () => {
    const result = detectCapabilities(
      'skill.js',
      'function writeFileSync() {}\nwriteFileSync();\n',
    );
    expect(result.fileSystemAccess).toBe(false);
  });
});

describe('detectCapabilities — networkAccess', () => {
  it('detects a bare global fetch(...) call', () => {
    const result = detectCapabilities('skill.js', "fetch('https://example.com');\n");
    expect(result.networkAccess).toBe(true);
  });

  it('detects https.request via a namespace require', () => {
    const result = detectCapabilities(
      'skill.js',
      "const https = require('https');\nhttps.request('https://example.com');\n",
    );
    expect(result.networkAccess).toBe(true);
  });

  it('detects a default-imported axios called directly', () => {
    const result = detectCapabilities(
      'skill.ts',
      "import axios from 'axios';\naxios('https://example.com');\n",
    );
    expect(result.networkAccess).toBe(true);
  });

  it('does not fire merely from importing a network module with no call through it', () => {
    const result = detectCapabilities('skill.js', "const axios = require('axios');\n");
    expect(result.networkAccess).toBe(false);
  });

  it('does not fire when fetch is only referenced, never called', () => {
    const result = detectCapabilities('skill.js', 'const handler = fetch;\n');
    expect(result.networkAccess).toBe(false);
  });
});

describe('detectCapabilities — destructiveKeywords (word-boundary fix)', () => {
  it('detects "delete" inside a camelCase function name (deleteFile) — the original word-boundary bug', () => {
    const result = detectCapabilities(
      'skill.js',
      'function deleteFile(path) {\n  return path;\n}\ndeleteFile("/tmp/x");\n',
    );
    expect(result.destructiveKeywords).toContain('delete');
  });

  it('detects "send" inside a camelCase function name (sendMessage)', () => {
    const result = detectCapabilities(
      'skill.js',
      'function sendMessage(bus, text) {\n  bus.publish(text);\n}\n',
    );
    expect(result.destructiveKeywords).toContain('send');
  });

  it('detects a keyword in an arrow function assigned to a variable', () => {
    const result = detectCapabilities(
      'skill.js',
      'const removeUser = (id) => {\n  db.remove(id);\n};\n',
    );
    expect(result.destructiveKeywords).toContain('remove');
  });

  it('detects a keyword in a call to a function not declared in this file', () => {
    const result = detectCapabilities(
      'skill.js',
      "import { transferFunds } from './bank.js';\ntransferFunds(100);\n",
    );
    expect(result.destructiveKeywords).toContain('transfer');
  });

  it('does NOT fire when the keyword only appears in a comment (fixes the old regex false positive that fixtures had to work around)', () => {
    const result = detectCapabilities(
      'skill.js',
      '// this function can delete a file\nfunction doNothing() {}\n',
    );
    expect(result.destructiveKeywords).toEqual([]);
  });

  it('does NOT fire when the keyword only appears in a string literal', () => {
    const result = detectCapabilities('skill.js', "const label = 'delete this later';\n");
    expect(result.destructiveKeywords).toEqual([]);
  });

  it('does not false-positive on a word that merely contains a keyword as a substring (deployment vs deploy is a real segment match, but "sender" is not "send")', () => {
    const result = detectCapabilities('skill.js', 'function sender() {}\nsender();\n');
    expect(result.destructiveKeywords).toEqual([]);
  });

  // PROPOSED_FIXES.md 2.4 — bare `.send()`/`.delete()`/`.remove()` method
  // calls are overwhelmingly container/response/DOM APIs (res.send,
  // Map#delete, Set#delete, socket.send, classList.remove), not a skill's
  // own irreversible action. They made nearly every real skill "destructive".
  it.each([
    ["res.send('ok');", 'Express response'],
    ['cache.delete(key);', 'Map#delete'],
    ['seen.delete(id);', 'Set#delete'],
    ['socket.send(payload);', 'WebSocket#send'],
    ["el.classList.remove('active');", 'DOMTokenList#remove'],
    ["params['delete']('q');", 'element-access form'],
  ])('does NOT fire on a generic member call: %s (%s)', (code) => {
    const result = detectCapabilities('skill.js', `${code}\n`);
    expect(result.destructiveKeywords).toEqual([]);
  });

  it('still fires on a member call whose name is more specific than the bare verb (client.sendEmail)', () => {
    const result = detectCapabilities('skill.js', 'client.sendEmail(to, body);\n');
    expect(result.destructiveKeywords).toEqual(['send']);
  });

  it('still fires on member calls for verbs that are not generic container methods (wallet.transfer, api.deploy)', () => {
    const result = detectCapabilities('skill.js', 'wallet.transfer(100);\napi.deploy();\n');
    expect(result.destructiveKeywords).toEqual(['deploy', 'transfer']);
  });

  it('still fires on a bare (non-member) call to a generic verb (send(x))', () => {
    const result = detectCapabilities(
      'skill.js',
      "import { send } from './mailer.js';\nsend(x);\n",
    );
    expect(result.destructiveKeywords).toEqual(['send']);
  });

  it('collects multiple distinct keywords, sorted and deduplicated', () => {
    const result = detectCapabilities(
      'skill.js',
      'function deleteFile() {}\nfunction deleteRecord() {}\nfunction sendEmail() {}\n',
    );
    expect(result.destructiveKeywords).toEqual(['delete', 'send']);
  });
});

describe('detectCapabilities — dynamicEval', () => {
  it('detects a bare eval(...) call', () => {
    const result = detectCapabilities('skill.js', "eval('doSomething()');\n");
    expect(result.dynamicEval).toBe(true);
  });

  it('detects new Function(...)', () => {
    const result = detectCapabilities('skill.js', "const f = new Function('return 1');\n");
    expect(result.dynamicEval).toBe(true);
  });

  it('detects a bare Function(...) call (no `new`)', () => {
    const result = detectCapabilities('skill.js', "const f = Function('return 1');\n");
    expect(result.dynamicEval).toBe(true);
  });

  it('detects a decode-then-execute chain (eval(atob(x)))', () => {
    const result = detectCapabilities('skill.js', 'eval(atob(payload));\n');
    expect(result.dynamicEval).toBe(true);
  });

  it('does not fire when eval only appears in a comment or string', () => {
    const result = detectCapabilities(
      'skill.js',
      "// don't eval(x) here\nconst msg = 'no eval() in this string either';\n",
    );
    expect(result.dynamicEval).toBe(false);
  });
});

describe('detectCapabilities — dataFlowToShellExec (CHAP-INJ-002 data-flow improvement)', () => {
  it('traces fetch -> res.text() -> exec(...), the command-relay fixture shape', () => {
    const result = detectCapabilities(
      'skill.js',
      "const { exec } = require('child_process');\nasync function relay(url) {\n  const res = await fetch(url);\n  const command = await res.text();\n  exec(command);\n}\n",
    );
    expect(result.dataFlowToShellExec).toBe(true);
  });

  it('traces a direct fetch result passed straight to exec', () => {
    const result = detectCapabilities(
      'skill.js',
      "const { exec } = require('child_process');\nasync function relay(url) {\n  const body = await fetch(url);\n  exec(body);\n}\n",
    );
    expect(result.dataFlowToShellExec).toBe(true);
  });

  it('traces an fs.readFileSync result into exec', () => {
    const result = detectCapabilities(
      'skill.js',
      "const fs = require('fs');\nconst { execSync } = require('child_process');\nconst script = fs.readFileSync('/tmp/x', 'utf8');\nexecSync(script);\n",
    );
    expect(result.dataFlowToShellExec).toBe(true);
  });

  it('does NOT fire when both capabilities are present but nothing traces (a mere shape-match)', () => {
    const result = detectCapabilities(
      'skill.js',
      "const { exec } = require('child_process');\nasync function relay(url) {\n  await fetch(url);\n  exec('ls');\n}\n",
    );
    expect(result.dataFlowToShellExec).toBe(false);
  });

  it('does not fire for shellExec alone with no network/fs capability', () => {
    const result = detectCapabilities(
      'skill.js',
      "const { exec } = require('child_process');\nexec('ls');\n",
    );
    expect(result.dataFlowToShellExec).toBe(false);
  });
});

describe('detectCapabilities — parsing', () => {
  it('parses TypeScript syntax (type annotations) without throwing', () => {
    const result = detectCapabilities(
      'skill.ts',
      "import { exec } from 'child_process';\nfunction run(command: string): void {\n  exec(command);\n}\n",
    );
    expect(result.shellExec).toBe(true);
  });

  it('never throws on malformed/unparseable input', () => {
    expect(() => detectCapabilities('skill.js', 'function( { [[[ ===')).not.toThrow();
  });

  it('returns all-false/empty for an empty file', () => {
    const result = detectCapabilities('skill.js', '');
    expect(result).toEqual({
      shellExec: false,
      fileSystemAccess: false,
      fileSystemScoped: false,
      networkAccess: false,
      destructiveKeywords: [],
      dynamicEval: false,
      dataFlowToShellExec: false,
    });
  });
});

describe('mergeCapabilities', () => {
  it('ORs boolean capabilities across files', () => {
    const merged = mergeCapabilities([
      {
        shellExec: true,
        fileSystemAccess: false,
        fileSystemScoped: false,
        networkAccess: false,
        destructiveKeywords: [],
        dynamicEval: false,
        dataFlowToShellExec: false,
      },
      {
        shellExec: false,
        fileSystemAccess: true,
        fileSystemScoped: false,
        networkAccess: false,
        destructiveKeywords: [],
        dynamicEval: false,
        dataFlowToShellExec: false,
      },
    ]);
    expect(merged.shellExec).toBe(true);
    expect(merged.fileSystemAccess).toBe(true);
  });

  it('unions destructiveKeywords across files, deduplicated and sorted', () => {
    const merged = mergeCapabilities([
      {
        shellExec: false,
        fileSystemAccess: false,
        fileSystemScoped: false,
        networkAccess: false,
        destructiveKeywords: ['send'],
        dynamicEval: false,
        dataFlowToShellExec: false,
      },
      {
        shellExec: false,
        fileSystemAccess: false,
        fileSystemScoped: false,
        networkAccess: false,
        destructiveKeywords: ['delete', 'send'],
        dynamicEval: false,
        dataFlowToShellExec: false,
      },
    ]);
    expect(merged.destructiveKeywords).toEqual(['delete', 'send']);
  });

  it('returns all-false/empty for zero files', () => {
    expect(mergeCapabilities([])).toEqual({
      shellExec: false,
      fileSystemAccess: false,
      fileSystemScoped: false,
      networkAccess: false,
      destructiveKeywords: [],
      dynamicEval: false,
      dataFlowToShellExec: false,
    });
  });
});
