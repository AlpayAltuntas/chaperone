import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { discoverAgent } from '../../src/discovery/index.js';
import { MCP_CONFIG_FILENAMES } from '../../src/discovery/mcpProfile.js';

// Phase 17 (improvement_plan.md 3.1) — the 'mcp' discovery profile, a
// real (not synthetic) config shape: the MCP server config format used
// by Claude Desktop, Claude Code, and other MCP clients.
describe("discoverAgent — 'mcp' profile", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-mcp-profile-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it.each(MCP_CONFIG_FILENAMES)('locates %s directly inside the target root', (filename) => {
    writeFileSync(
      path.join(dir, filename),
      JSON.stringify({ mcpServers: { demo: { command: 'npx', args: ['-y', 'demo-server'] } } }),
    );

    const { model, targetRootResolved } = discoverAgent({ targetPath: dir, profile: 'mcp' });

    expect(targetRootResolved).toBe(true);
    expect(model.config.path).toBe(path.join(dir, filename));
    expect(model.skills).toHaveLength(1);
    expect(model.skills[0]?.name).toBe('demo');
  });

  it('reports a skipped entry (not an error) when no MCP config exists', () => {
    const { model, targetRootResolved } = discoverAgent({ targetPath: dir, profile: 'mcp' });

    expect(targetRootResolved).toBe(true);
    expect(model.skills).toEqual([]);
    expect(model.skipped).toHaveLength(1);
    expect(model.skipped[0]?.reason).toContain('no MCP config found');
  });

  it('reports a skipped entry (not a throw) for malformed JSON', () => {
    writeFileSync(path.join(dir, '.mcp.json'), '{ not json');

    const { model, targetRootResolved } = discoverAgent({ targetPath: dir, profile: 'mcp' });

    expect(targetRootResolved).toBe(true);
    expect(model.skipped.some((s) => s.reason.includes('unparseable MCP config'))).toBe(true);
  });

  it('extracts a literal secret from an env block via the shared maskConfig masking pipeline', () => {
    writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          github: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-github'],
            env: { GITHUB_PERSONAL_ACCESS_TOKEN: 'ghp_EXAMPLE1234567890abcdefghijklmnop' },
          },
        },
      }),
    );

    const { model } = discoverAgent({ targetPath: dir, profile: 'mcp' });

    const field = model.config.secretFields.find(
      (f) => f.keyPath === 'mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN',
    );
    expect(field).toBeDefined();
    expect(field?.looksLikeEnvReference).toBe(false);
    expect(field?.displayValue).not.toContain('EXAMPLE1234567890abcdefghijklmnop');
    expect(JSON.stringify(model)).not.toContain('EXAMPLE1234567890abcdefghijklmnop');
  });

  it('does not flag an env-var-reference value as a literal secret', () => {
    writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          github: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-github@2.1.0'],
            env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${GITHUB_PERSONAL_ACCESS_TOKEN}' },
          },
        },
      }),
    );

    const { model } = discoverAgent({ targetPath: dir, profile: 'mcp' });

    const field = model.config.secretFields.find(
      (f) => f.keyPath === 'mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN',
    );
    expect(field?.looksLikeEnvReference).toBe(true);
  });

  it('derives pinnedRef: true from an exact @version, false from a bare package name, null for a remote/url server', () => {
    writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          pinned: { command: 'npx', args: ['-y', '@scope/server@2.1.0'] },
          unpinned: { command: 'npx', args: ['-y', '@scope/server'] },
          remote: { url: 'https://mcp.example.com/sse' },
        },
      }),
    );

    const { model } = discoverAgent({ targetPath: dir, profile: 'mcp' });

    const byName = Object.fromEntries(model.skills.map((s) => [s.name, s]));
    expect(byName['pinned']?.provenance.pinnedRef).toBe(true);
    expect(byName['unpinned']?.provenance.pinnedRef).toBe(false);
    expect(byName['remote']?.provenance.pinnedRef).toBeNull();
    expect(byName['remote']?.provenance.sourceUrl).toBe('https://mcp.example.com/sse');
  });

  it('treats @latest as unpinned, not pinned', () => {
    writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: { demo: { command: 'npx', args: ['-y', '@scope/server@latest'] } },
      }),
    );

    const { model } = discoverAgent({ targetPath: dir, profile: 'mcp' });

    expect(model.skills[0]?.provenance.pinnedRef).toBe(false);
  });

  it('leaves every skill capability false — no source to statically analyze for an MCP server', () => {
    writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({ mcpServers: { demo: { command: 'npx', args: ['-y', 'demo-server'] } } }),
    );

    const { model } = discoverAgent({ targetPath: dir, profile: 'mcp' });

    expect(model.skills[0]?.capabilities).toEqual({
      shellExec: false,
      fileSystemAccess: false,
      fileSystemScoped: false,
      networkAccess: false,
      destructiveKeywords: [],
      dynamicEval: false,
      dataFlowToShellExec: false,
    });
  });

  it('reports the MCP config file permission fact, feeding CHAP-SEC-003', () => {
    const configPath = path.join(dir, '.mcp.json');
    writeFileSync(configPath, JSON.stringify({ mcpServers: {} }));
    chmodSync(configPath, 0o644);

    const { model } = discoverAgent({ targetPath: dir, profile: 'mcp' });

    const fact = model.permissions.find((p) => p.path === configPath);
    expect(fact?.groupOrOtherReadable).toBe(true);
  });

  it('defaults to the current working directory when no explicit path is given', () => {
    writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({ mcpServers: { demo: { command: 'npx', args: ['-y', 'demo-server'] } } }),
    );
    const originalCwd = process.cwd();
    process.chdir(dir);
    try {
      const { model } = discoverAgent({ profile: 'mcp' });
      expect(model.skills).toHaveLength(1);
    } finally {
      process.chdir(originalCwd);
    }
  });

  it('ignores an mcpServers entry shaped like neither a stdio nor a remote server', () => {
    writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({ mcpServers: { broken: { nothingUseful: true } } }),
    );

    const { model } = discoverAgent({ targetPath: dir, profile: 'mcp' });

    expect(model.skills).toEqual([]);
  });
});

describe("discoverAgent — 'default' profile is unaffected by the mcp profile's existence", () => {
  it('still uses the fictional config.yaml-based discovery when profile is omitted', () => {
    const { model, targetRootResolved } = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'clean-agent'),
    });

    expect(targetRootResolved).toBe(true);
    expect(model.config.format).toBe('yaml');
  });

  it('behaves identically whether profile is omitted or explicitly "default"', () => {
    const withoutProfile = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'clean-agent'),
    });
    const withDefaultProfile = discoverAgent({
      targetPath: path.join('test', 'fixtures', 'clean-agent'),
      profile: 'default',
    });

    expect(withDefaultProfile.model.config.path).toBe(withoutProfile.model.config.path);
    expect(withDefaultProfile.model.skills.length).toBe(withoutProfile.model.skills.length);
  });
});
