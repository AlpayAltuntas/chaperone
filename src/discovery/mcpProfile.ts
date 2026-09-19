import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { AgentModel, InspectedEntry, SkippedEntry, Skill } from '../model/types.js';
import { maskConfig } from './configParser.js';
import { errorMessage } from './errors.js';
import { emptyModel, type DiscoveryOptions, type DiscoveryResult } from './index.js';
import { isRecord } from './jsonUtils.js';
import { getFilePermissionFact } from './permissions.js';

// The real, second discovery "profile" (improvement_plan.md 3.1/Phase 17)
// — a genuine (not synthetic) config shape: the MCP (Model Context
// Protocol) server config format used by Claude Desktop, Claude Code,
// and other MCP clients (`.mcp.json`/`mcp.json`/`claude_desktop_config.json`,
// a top-level `{"mcpServers": {"<name>": {command/args/env | url/headers}}}`
// object). Deliberately NOT a full second check registry — mapped onto
// the existing AgentModel/29-check catalog wherever a check's heuristic
// genuinely transfers (see DECISIONS.md, Phase 17, for exactly which
// checks fire and why the rest correctly stay silent rather than being
// forced to "apply").

export const MCP_CONFIG_FILENAMES = ['.mcp.json', 'mcp.json', 'claude_desktop_config.json'];

interface McpStdioServer {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

interface McpRemoteServer {
  url: string;
  headers?: Record<string, string>;
}

function isMcpStdioServer(value: unknown): value is McpStdioServer {
  return isRecord(value) && typeof value['command'] === 'string';
}

function isMcpRemoteServer(value: unknown): value is McpRemoteServer {
  return isRecord(value) && typeof value['url'] === 'string';
}

/** Locates an MCP config file directly inside a resolved root, trying known filenames in order — same pattern as configLocator.ts's locateConfigFile. */
function locateMcpConfigFile(root: string): string | null {
  for (const filename of MCP_CONFIG_FILENAMES) {
    const candidate = path.join(root, filename);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

/**
 * A package/command is "pinned" when an `args` entry names an exact
 * version (`@modelcontextprotocol/server-github@2.1.0`), the same
 * question `extractProvenance`'s semver check asks for the default
 * profile's skills. A bare package name (`npx -y <pkg>`, the common
 * real-world form) floats to whatever that package's `latest` dist-tag
 * currently resolves to — unpinned. `null` (not `false`) for a remote/
 * URL server: there is no package/version concept to be pinned or not,
 * so CHAP-SUP-001 reports "no version/ref info found" rather than a
 * misleading "unpinned".
 */
function detectPinnedRef(server: McpStdioServer | McpRemoteServer): boolean | null {
  if (!('args' in server)) {
    return null;
  }
  const args = server.args ?? [];
  return args.some((arg) => /^@?[^@\s]+@\d+\.\d+\.\d+/.test(arg) && !arg.endsWith('@latest'));
}

/** Discovers an MCP server config and normalizes it into the same AgentModel shape the default profile produces, so the existing check catalog runs against it unmodified. */
export function discoverMcpAgent(options: DiscoveryOptions): DiscoveryResult {
  const inspected: InspectedEntry[] = [];
  const skipped: SkippedEntry[] = [];

  // MCP configs are conventionally project-scoped (checked in alongside
  // a repo), not home-directory-scoped like the default profile's
  // fictional install roots — so "no explicit path" means "look in the
  // current directory", not a probed list under $HOME.
  const targetRoot = path.resolve(options.targetPath ?? process.cwd());

  const configPath = locateMcpConfigFile(targetRoot);
  if (configPath === null) {
    skipped.push({
      path: targetRoot,
      reason: `no MCP config found (tried: ${MCP_CONFIG_FILENAMES.join(', ')})`,
    });
    return { targetRootResolved: true, model: emptyModel(targetRoot, inspected, skipped) };
  }

  let rawParsed: unknown;
  try {
    rawParsed = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch (err) {
    skipped.push({ path: configPath, reason: `unparseable MCP config: ${errorMessage(err)}` });
    return { targetRootResolved: true, model: emptyModel(targetRoot, inspected, skipped) };
  }
  inspected.push({ path: configPath, kind: 'config' });

  // Reused verbatim from the default profile (configParser.ts): walks
  // ANY JSON-shaped tree for secret-looking keys, regardless of nesting
  // — an MCP server's `env`/`headers` block is just more tree to it.
  const { data, secretFields } = maskConfig(rawParsed);

  const mcpServers =
    isRecord(rawParsed) && isRecord(rawParsed['mcpServers']) ? rawParsed['mcpServers'] : {};
  const skills: Skill[] = Object.entries(mcpServers)
    .filter((entry): entry is [string, McpStdioServer | McpRemoteServer] => {
      const [, value] = entry;
      return isMcpStdioServer(value) || isMcpRemoteServer(value);
    })
    .map(([name, server]) => mcpServerToSkill(name, server, configPath));

  const permissions = [getFilePermissionFact(configPath)];

  const model: AgentModel = {
    ...emptyModel(targetRoot, inspected, skipped),
    config: { path: configPath, format: 'json', data, secretFields },
    permissions,
    skills,
  };

  return { targetRootResolved: true, model };
}

function mcpServerToSkill(
  name: string,
  server: McpStdioServer | McpRemoteServer,
  configPath: string,
): Skill {
  return {
    name,
    dir: path.dirname(configPath),
    manifestPath: configPath,
    // No source to statically analyze for an MCP server — it's an
    // external process/endpoint, not code Chaperone reads. Every
    // capability stays false rather than guessed at.
    capabilities: {
      shellExec: false,
      fileSystemAccess: false,
      fileSystemScoped: false,
      networkAccess: false,
      destructiveKeywords: [],
      dynamicEval: false,
      dataFlowToShellExec: false,
    },
    provenance: {
      sourceUrl: 'url' in server ? server.url : null,
      pinnedRef: detectPinnedRef(server),
      author: null,
    },
    // No separate manifest/lockfile concept for an MCP server entry —
    // the MCP config itself is already the provenance signal above, so
    // CHAP-SUP-002/003/006 (npm-manifest-shaped checks) correctly stay
    // silent rather than being forced onto a shape they don't fit.
    dependencies: { manifestPath: null, lockfilePath: null, names: [] },
    installScripts: { scripts: [] },
    confirmationRequired: null,
    domainAllowlist: null,
  };
}
