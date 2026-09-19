import { describe, expect, it } from 'vitest';
import { detectPythonCapabilities } from '../../src/discovery/pythonCapabilities.js';

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

  it('detects a destructive keyword as a standalone word', () => {
    const capabilities = detectPythonCapabilities('# Delete old cache files without confirmation.');
    expect(capabilities.destructiveKeywords).toEqual(['delete']);
  });

  it('has the same documented fragility as the pre-Phase-10 JS approach: an identifier joined by an underscore is not a word boundary', () => {
    // `\bdelete\b` never matches inside `delete_file` — no non-word
    // boundary between `e` and `_` (both are \w). Deliberately NOT
    // fixed here (see astCapabilities.ts's splitWordSegments, which
    // Phase 16 explicitly does not port to Python) — this is the
    // documented v1 limitation, not a bug.
    const capabilities = detectPythonCapabilities(
      'def delete_file(path):\n    pathlib.Path(path).unlink()',
    );
    expect(capabilities.destructiveKeywords).toEqual([]);
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
    });
  });
});
