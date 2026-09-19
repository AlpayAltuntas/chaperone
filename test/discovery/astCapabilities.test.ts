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

  it('collects multiple distinct keywords, sorted and deduplicated', () => {
    const result = detectCapabilities(
      'skill.js',
      'function deleteFile() {}\nfunction deleteRecord() {}\nfunction sendEmail() {}\n',
    );
    expect(result.destructiveKeywords).toEqual(['delete', 'send']);
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
      },
      {
        shellExec: false,
        fileSystemAccess: true,
        fileSystemScoped: false,
        networkAccess: false,
        destructiveKeywords: [],
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
      },
      {
        shellExec: false,
        fileSystemAccess: false,
        fileSystemScoped: false,
        networkAccess: false,
        destructiveKeywords: ['delete', 'send'],
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
    });
  });
});
