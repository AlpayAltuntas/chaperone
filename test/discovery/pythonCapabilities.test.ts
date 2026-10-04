import { describe, expect, it } from 'vitest';
import { detectPythonCapabilities } from '../../src/discovery/pythonCapabilities.js';
import {
  parsePyprojectToml,
  parseRequirementsTxt,
} from '../../src/discovery/pythonDependencies.js';

describe('detectPythonCapabilities — Phase 16 (improvement_plan.md 1.9), regex-based first cut', () => {
  it('detects subprocess-based shell execution', () => {
    const capabilities = detectPythonCapabilities('subprocess.run(["ls", "-la"])');
    expect(capabilities.shellExec).toBe(true);
  });

  it('detects os.system-based shell execution', () => {
    const capabilities = detectPythonCapabilities('os.system("rm -rf /tmp/x")');
    expect(capabilities.shellExec).toBe(true);
  });

  it('does not flag shellExec for unrelated code', () => {
    const capabilities = detectPythonCapabilities('print("hello world")');
    expect(capabilities.shellExec).toBe(false);
  });

  it('detects requests-based network access', () => {
    const capabilities = detectPythonCapabilities('requests.get("https://example.invalid")');
    expect(capabilities.networkAccess).toBe(true);
  });

  it('detects urllib/socket network access', () => {
    expect(
      detectPythonCapabilities('import urllib.request\nurllib.request.urlopen(url)').networkAccess,
    ).toBe(true);
    expect(
      detectPythonCapabilities('socket.socket(socket.AF_INET, socket.SOCK_STREAM)').networkAccess,
    ).toBe(true);
  });

  it('detects eval/exec/__import__ as dynamicEval', () => {
    expect(detectPythonCapabilities('eval(payload)').dynamicEval).toBe(true);
    expect(detectPythonCapabilities('exec(compiled_code)').dynamicEval).toBe(true);
    expect(detectPythonCapabilities('mod = __import__(module_name)').dynamicEval).toBe(true);
  });

  it('detects direct filesystem writes (os.remove, shutil.rmtree, open in write mode)', () => {
    expect(detectPythonCapabilities('os.remove(path)').fileSystemAccess).toBe(true);
    expect(detectPythonCapabilities('shutil.rmtree(path)').fileSystemAccess).toBe(true);
    expect(detectPythonCapabilities('open(path, "w")').fileSystemAccess).toBe(true);
  });

  it('does not flag fileSystemAccess for a read-mode open', () => {
    expect(detectPythonCapabilities('open(path, "r")').fileSystemAccess).toBe(false);
  });

  it('matches a write-mode open even with a nested call in the path argument', () => {
    // A naive `open\([^)]*,...` regex would stop at the inner call's own
    // closing paren — this is the exact bug caught while building the
    // clean Python fixture (test/fixtures/clean-agent/skills/py-notes).
    const source = 'open(os.path.join(WORKSPACE, name), "w", encoding="utf-8")';
    expect(detectPythonCapabilities(source).fileSystemAccess).toBe(true);
  });

  it('detects fileSystemScoped via os.path.dirname(__file__) or a WORKSPACE/SANDBOX/SCOPED-named variable', () => {
    expect(
      detectPythonCapabilities('WORKSPACE = os.path.join(os.path.dirname(__file__), "workspace")')
        .fileSystemScoped,
    ).toBe(true);
    expect(detectPythonCapabilities('SANDBOX_DIR = "/tmp/sandbox"').fileSystemScoped).toBe(true);
    expect(detectPythonCapabilities('os.remove(user_supplied_path)').fileSystemScoped).toBe(false);
  });

  // PROPOSED_FIXES.md 2.4: only module-level `def` names count, split into
  // word segments, so a keyword in a comment or string no longer does and
  // `delete_file` now does.
  it('detects a destructive keyword in a module-level function name', () => {
    const capabilities = detectPythonCapabilities(
      'def delete_file(path):\n    pathlib.Path(path).unlink()',
      'skill.py',
    );
    expect(capabilities.destructiveKeywords).toEqual(['delete']);
    expect(capabilities.evidence).toContainEqual({
      capability: 'destructive',
      file: 'skill.py',
      line: 1,
      api: 'delete_file',
    });
  });

  it.each([
    ['a comment', '# Delete old cache files without confirmation.\ndef run():\n    pass'],
    ['a string', 'def run():\n    subprocess.run(["find", ".", "-delete"])'],
    ['a nested helper', 'def run():\n    def delete_tmp():\n        pass'],
  ])('ignores a destructive keyword in %s', (_label, source) => {
    expect(detectPythonCapabilities(source).destructiveKeywords).toEqual([]);
  });

  it('records the line of each capability', () => {
    const source = 'import subprocess\n\n\ndef run(c):\n    subprocess.run(c)\n    eval(c)\n';
    const { evidence } = detectPythonCapabilities(source, 'x.py');
    expect(evidence).toEqual([
      { capability: 'shellExec', file: 'x.py', line: 5, api: 'subprocess.run' },
      { capability: 'dynamicEval', file: 'x.py', line: 6, api: 'eval' },
    ]);
  });

  it('never sets dataFlowToShellExec — Phase 16 is capability detection only, not a ported taint analysis', () => {
    const source = 'data = requests.get(url).text\nsubprocess.run(data)';
    expect(detectPythonCapabilities(source).dataFlowToShellExec).toBe(false);
  });

  it('returns every capability false for a file with none of the tracked patterns', () => {
    const capabilities = detectPythonCapabilities('def add(a, b):\n    return a + b\n');
    expect(capabilities).toEqual({
      shellExec: false,
      fileSystemAccess: false,
      fileSystemScoped: false,
      networkAccess: false,
      destructiveKeywords: [],
      dynamicEval: false,
      dataFlowToShellExec: false,
      evidence: [],
    });
  });
});

// PROPOSED_FIXES.md 3.4.
describe('detectPythonCapabilities — aliases, comments, strings (3.4)', () => {
  it.each([
    [
      'from subprocess import run',
      'from subprocess import run\nrun(cmd, shell=True)',
      'shellExec',
      'subprocess.run',
    ],
    [
      'import subprocess as sp',
      'import subprocess as sp\nsp.Popen(cmd)',
      'shellExec',
      'subprocess.Popen',
    ],
    [
      'from os import system as sh',
      'from os import system as sh\nsh(cmd)',
      'shellExec',
      'os.system',
    ],
    [
      'asyncio.create_subprocess_shell',
      'import asyncio\nawait asyncio.create_subprocess_shell(cmd)',
      'shellExec',
      'asyncio.create_subprocess_shell',
    ],
    ['pty.spawn', 'import pty\npty.spawn("/bin/sh")', 'shellExec', 'pty.spawn'],
    [
      'multi-line from-import',
      'from subprocess import (\n    check_output,\n    PIPE,\n)\ncheck_output(c)',
      'shellExec',
      'subprocess.check_output',
    ],
    ['httpx', 'import httpx\nhttpx.get(url)', 'networkAccess', 'httpx.get'],
    [
      'aiohttp',
      'import aiohttp\naiohttp.ClientSession()',
      'networkAccess',
      'aiohttp.ClientSession',
    ],
    ['urllib3', 'import urllib3\nurllib3.PoolManager()', 'networkAccess', 'urllib3.PoolManager'],
    ['pickle.loads', 'import pickle\npickle.loads(blob)', 'dynamicEval', 'pickle.loads'],
    ['marshal.loads', 'import marshal\nmarshal.loads(blob)', 'dynamicEval', 'marshal.loads'],
    [
      'yaml.load without a safe loader',
      'import yaml\nyaml.load(text)',
      'dynamicEval',
      'yaml.load (no SafeLoader)',
    ],
    [
      'pathlib write_text',
      'from pathlib import Path\nPath(p).write_text(d)',
      'fileSystemAccess',
      '.write_text',
    ],
  ])('detects %s', (_label, source, capability, api) => {
    const { evidence } = detectPythonCapabilities(source, 'x.py');
    expect(evidence).toContainEqual(expect.objectContaining({ capability, api }));
  });

  it.each([
    ['cursor.exec', 'cursor.exec("SELECT 1")'],
    ['a call in a comment', '# subprocess.run(cmd)\nx = 1'],
    ['a call in a docstring', '"""\nos.system(cmd) is dangerous\n"""\nx = 1'],
    ['a call in a string', 'msg = "eval(x) is not run"'],
    ['yaml.load with SafeLoader', 'import yaml\nyaml.load(text, Loader=yaml.SafeLoader)'],
    ['yaml.safe_load', 'import yaml\nyaml.safe_load(text)'],
    ['a local function named run', 'def run(x):\n    return x\nrun(1)'],
  ])('ignores %s', (_label, source) => {
    const capabilities = detectPythonCapabilities(source);
    expect(capabilities.shellExec || capabilities.dynamicEval || capabilities.networkAccess).toBe(
      false,
    );
  });
});

describe('Python dependency manifests (3.4)', () => {
  it('parses requirements.txt, ignoring options and comments', () => {
    expect(
      parseRequirementsTxt(
        '# deps\nrequests>=2.31 ; python_version>"3.8"\n-r other.txt\nhttpx[http2]==0.27.0  # client\n\nPyYAML\n',
      ),
    ).toEqual({
      versionsByName: { requests: '>=2.31', httpx: '==0.27.0', pyyaml: '' },
      hashPinned: false,
    });
  });

  it('treats a fully hashed requirements.txt as its own lockfile', () => {
    expect(
      parseRequirementsTxt(
        'requests==2.31.0 \\\n    --hash=sha256:abc\nidna==3.6 --hash=sha256:def\n',
      ).hashPinned,
    ).toBe(true);
  });

  it('parses [project] and [tool.poetry] dependencies from pyproject.toml', () => {
    const toml = [
      '[project]',
      'name = "x"',
      'dependencies = [',
      '  "requests>=2",',
      "  'rich',",
      ']',
      '',
      '[tool.poetry.dependencies]',
      'python = "^3.11"',
      'httpx = "^0.27"',
      '',
    ].join('\n');
    expect(parsePyprojectToml(toml)).toEqual({ requests: '>=2', rich: '', httpx: '^0.27' });
  });
});
