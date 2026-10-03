import { readFileSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type {
  AgentModel,
  CapabilityEvidence,
  ContainerLaunch,
  InspectedEntry,
  Skill,
  SkillLaunch,
  SkippedEntry,
} from '../model/types.js';
import { resolveExplicitTarget } from './configLocator.js';
import { buildKeyLineIndex, maskConfig, maskSecretValue } from './configParser.js';
import { containerRunPrivileges } from './containerPrivileges.js';
import { errorMessage } from './errors.js';
import { emptyModel, type DiscoveryOptions, type DiscoveryResult } from './index.js';
import { isRecord } from './jsonUtils.js';
import { getFilePermissionFact } from './permissions.js';
import { detectSecretValue } from './secretValuePatterns.js';
import { matchDangerousPatterns } from './skillsScanner.js';

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

// Project-scoped locations, relative to the target root, tried in order
// (PROPOSED_FIXES.md 3.9). VS Code and Cursor keep theirs in a dot-folder.
const PROJECT_MCP_CONFIGS = [
  ...MCP_CONFIG_FILENAMES,
  path.join('.vscode', 'mcp.json'),
  path.join('.cursor', 'mcp.json'),
];

/** User-level MCP client configs, probed only when no path is given and the current directory has none. */
export function globalMcpConfigCandidates(
  home: string = os.homedir(),
  platform: NodeJS.Platform = process.platform,
  appData: string | undefined = process.env['APPDATA'],
): string[] {
  const claudeDesktop =
    platform === 'darwin'
      ? path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
      : platform === 'win32'
        ? path.join(
            appData ?? path.join(home, 'AppData', 'Roaming'),
            'Claude',
            'claude_desktop_config.json',
          )
        : path.join(home, '.config', 'Claude', 'claude_desktop_config.json');
  return [claudeDesktop, path.join(home, '.cursor', 'mcp.json'), path.join(home, '.claude.json')];
}

interface ServerEntry {
  name: string;
  server: McpStdioServer | McpRemoteServer;
  /** The server's key path in the config, for line numbers (`mcpServers.github`). */
  keyPath: string;
}

interface McpStdioServer {
  command: string;
  args?: unknown;
  env?: unknown;
}

interface McpRemoteServer {
  url: string;
  headers?: unknown;
}

function isMcpStdioServer(value: unknown): value is McpStdioServer {
  return isRecord(value) && typeof value['command'] === 'string';
}

function isMcpRemoteServer(value: unknown): value is McpRemoteServer {
  return isRecord(value) && typeof value['url'] === 'string';
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function recordKeys(value: unknown): string[] {
  return isRecord(value) ? Object.keys(value) : [];
}

/**
 * Every server in an MCP config. Claude Desktop, Claude Code, and Cursor
 * use a top-level `mcpServers` object; VS Code uses `servers`; and
 * `~/.claude.json` also nests per-project `mcpServers` under `projects`.
 */
function collectServers(parsed: unknown): ServerEntry[] {
  if (!isRecord(parsed)) {
    return [];
  }
  const entries: ServerEntry[] = [];
  const addFrom = (container: unknown, prefix: string, label: (name: string) => string): void => {
    if (!isRecord(container)) {
      return;
    }
    for (const [name, server] of Object.entries(container)) {
      if (isMcpStdioServer(server) || isMcpRemoteServer(server)) {
        entries.push({ name: label(name), server, keyPath: `${prefix}.${name}` });
      }
    }
  };
  addFrom(parsed['mcpServers'], 'mcpServers', (name) => name);
  addFrom(parsed['servers'], 'servers', (name) => name);
  const projects = parsed['projects'];
  if (isRecord(projects)) {
    for (const [project, settings] of Object.entries(projects)) {
      if (isRecord(settings)) {
        addFrom(
          settings['mcpServers'],
          `projects.${project}.mcpServers`,
          (name) => `${name} (${project})`,
        );
      }
    }
  }
  return entries;
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
  const args = stringArray(server.args);
  return args.some((arg) => /^@?[^@\s]+@\d+\.\d+\.\d+/.test(arg) && !arg.endsWith('@latest'));
}

/** Locates an MCP config directly inside a resolved root, trying known locations in order. */
function locateMcpConfigFile(root: string): string | null {
  for (const relative of PROJECT_MCP_CONFIGS) {
    const candidate = path.join(root, relative);
    if (isFile(candidate)) {
      return candidate;
    }
  }
  return null;
}

function isFile(candidate: string): boolean {
  try {
    return statSync(candidate).isFile();
  } catch {
    return false;
  }
}

/** Discovers an MCP server config and normalizes it into the same AgentModel shape the default profile produces, so the existing check catalog runs against it unmodified. */
export function discoverMcpAgent(options: DiscoveryOptions): DiscoveryResult {
  const inspected: InspectedEntry[] = [];
  const skipped: SkippedEntry[] = [];

  // MCP configs are usually project-scoped, so "no explicit path" means
  // the current directory first, then the user-level client configs
  // (Claude Desktop, Cursor, Claude Code's ~/.claude.json).
  let targetRoot = path.resolve(options.targetPath ?? process.cwd());
  let configPath: string | null = null;
  if (options.targetPath !== undefined) {
    // A path to any config file is used as-is (`.vscode/mcp.json`,
    // `~/.claude.json`), not only the conventional names.
    if (isFile(targetRoot)) {
      configPath = targetRoot;
      targetRoot = path.dirname(targetRoot);
    } else {
      const explicit = resolveExplicitTarget(options.targetPath, MCP_CONFIG_FILENAMES);
      if (explicit.root === null) {
        skipped.push({ path: targetRoot, reason: explicit.reason });
        return { targetRootResolved: false, model: emptyModel(targetRoot, inspected, skipped) };
      }
      targetRoot = explicit.root;
    }
  }
  configPath ??= locateMcpConfigFile(targetRoot);
  if (configPath === null && options.targetPath === undefined) {
    configPath = globalMcpConfigCandidates().find(isFile) ?? null;
    if (configPath !== null) {
      targetRoot = path.dirname(configPath);
    }
  }

  // Nothing scanned is never reported as a clean pass (PROPOSED_FIXES.md
  // 2.1): a missing or unparseable MCP config, or one with no servers,
  // leaves targetRootResolved false, so the CLI exits non-zero.
  if (configPath === null) {
    skipped.push({
      path: targetRoot,
      reason: `no MCP config found (tried: ${PROJECT_MCP_CONFIGS.join(', ')}${options.targetPath === undefined ? ', and the user-level Claude Desktop/Cursor/Claude Code configs' : ''})`,
    });
    return { targetRootResolved: false, model: emptyModel(targetRoot, inspected, skipped) };
  }

  let rawParsed: unknown;
  let source: string;
  try {
    source = readFileSync(configPath, 'utf8');
    rawParsed = JSON.parse(source);
  } catch (err) {
    skipped.push({ path: configPath, reason: `unparseable MCP config: ${errorMessage(err)}` });
    return { targetRootResolved: false, model: emptyModel(targetRoot, inspected, skipped) };
  }
  inspected.push({ path: configPath, kind: 'config' });

  const servers = collectServers(rawParsed);
  if (servers.length === 0) {
    skipped.push({
      path: configPath,
      reason: 'MCP config defines no servers (no `mcpServers` or `servers` entries)',
    });
    return { targetRootResolved: false, model: emptyModel(targetRoot, inspected, skipped) };
  }

  // Reused verbatim from the default profile (configParser.ts): walks
  // ANY JSON-shaped tree for secret-looking keys and values — an MCP
  // server's `env`/`headers`/`args` are just more tree to it.
  const keyLines = buildKeyLineIndex(source);
  const masked = maskConfig(rawParsed);
  const secretFields = masked.secretFields.map((field) => ({
    ...field,
    line: keyLines[field.keyPath] ?? null,
  }));

  const analyses = servers.map((entry) => analyzeServer(entry, configPath, keyLines));

  const model: AgentModel = {
    ...emptyModel(targetRoot, inspected, skipped),
    config: { path: configPath, format: 'json', data: masked.data, secretFields, keyLines },
    permissions: [getFilePermissionFact(configPath, 'config')],
    skills: analyses.map((a) => a.skill),
    containers: analyses.flatMap((a) => (a.container === null ? [] : [a.container])),
  };

  return { targetRootResolved: true, model };
}

// Shell binaries, and the flag that makes each run a command string.
const SHELL_COMMAND_FLAGS: ReadonlyMap<string, readonly string[]> = new Map([
  ['sh', ['-c']],
  ['bash', ['-c']],
  ['zsh', ['-c']],
  ['dash', ['-c']],
  ['fish', ['-c']],
  ['cmd', ['/c', '/C', '/k', '/K']],
  ['powershell', ['-Command', '-command', '-c', '-EncodedCommand', '-e']],
  ['pwsh', ['-Command', '-command', '-c', '-EncodedCommand', '-e']],
]);

// Reference filesystem servers, by package (with or without a version).
const FILESYSTEM_SERVER =
  /^(?:@modelcontextprotocol\/server-filesystem|mcp-server-filesystem|@modelcontextprotocol\/server-filesystem-.*)(?:@.*)?$/;

/** A path argument that grants the whole disk or the whole home directory. */
function isBroadRoot(arg: string): boolean {
  const trimmed = arg.trim().replace(/[/\\]+$/, '');
  return (
    trimmed === '' ||
    trimmed === '~' ||
    trimmed === '$HOME' ||
    trimmed === '${HOME}' ||
    trimmed === '%USERPROFILE%' ||
    /^[A-Za-z]:$/.test(trimmed)
  );
}

function maskArg(arg: string): string {
  return detectSecretValue(arg, maskSecretValue)?.masked ?? arg;
}

interface ServerAnalysis {
  skill: Skill;
  container: ContainerLaunch | null;
}

/**
 * Maps one MCP server to a Skill (PROPOSED_FIXES.md 3.9). There's no
 * source to read, so capabilities come from how the server is launched:
 * a shell run with `-c` is shell execution (and its command string is
 * checked like an install script), a filesystem server rooted at `/`,
 * `~`, or a drive root is unscoped filesystem access, and a remote
 * server is network access. A `docker`/`podman run` launch is also
 * reported as a container, with any host privileges it grants.
 */
function analyzeServer(
  { name, server, keyPath }: ServerEntry,
  configPath: string,
  keyLines: Readonly<Record<string, number>>,
): ServerAnalysis {
  const evidence: CapabilityEvidence[] = [];
  const installScripts: Array<{ path: string; dangerousPatterns: string[] }> = [];
  let container: ContainerLaunch | null = null;
  let launch: SkillLaunch;
  let shellExec = false;
  let fileSystemAccess = false;
  let fileSystemScoped = false;
  let networkAccess = false;

  if (isMcpStdioServer(server)) {
    const args = stringArray(server.args);
    launch = {
      kind: 'stdio',
      command: server.command,
      args: args.map(maskArg),
      envKeys: recordKeys(server.env),
    };
    const commandLine = keyLines[`${keyPath}.command`] ?? keyLines[keyPath] ?? null;
    const binary = path
      .basename(server.command)
      .replace(/\.exe$/i, '')
      .toLowerCase();
    const shellFlags = SHELL_COMMAND_FLAGS.get(binary);
    const flagIndex = shellFlags === undefined ? -1 : args.findIndex((a) => shellFlags.includes(a));
    if (flagIndex !== -1) {
      shellExec = true;
      evidence.push({
        capability: 'shellExec',
        file: configPath,
        line: commandLine,
        api: `${binary} ${args[flagIndex] ?? ''}`,
      });
      const script = args.slice(flagIndex + 1).join(' ');
      const dangerousPatterns = matchDangerousPatterns(script, true);
      if (dangerousPatterns.length > 0) {
        installScripts.push({ path: configPath, dangerousPatterns });
      }
    }
    const fsIndex = args.findIndex((a) => FILESYSTEM_SERVER.test(a));
    if (fsIndex !== -1) {
      const roots = args.slice(fsIndex + 1).filter((a) => !a.startsWith('-'));
      fileSystemAccess = true;
      const broad = roots.filter(isBroadRoot);
      fileSystemScoped = roots.length > 0 && broad.length === 0;
      evidence.push({
        capability: 'fileSystemAccess',
        file: configPath,
        line: keyLines[`${keyPath}.args`] ?? commandLine,
        api: `filesystem server (${roots.length > 0 ? roots.join(', ') : 'no root given'})`,
        scoped: fileSystemScoped,
      });
    }
    const hostPrivileges = containerRunPrivileges(server.command, args);
    if (hostPrivileges !== null && hostPrivileges.length > 0) {
      container = { name, source: configPath, line: commandLine, hostPrivileges };
    }
  } else {
    const masked = detectSecretValue(server.url, maskSecretValue)?.masked ?? server.url;
    launch = { kind: 'remote', url: masked, headerKeys: recordKeys(server.headers) };
    networkAccess = true;
    evidence.push({
      capability: 'networkAccess',
      file: configPath,
      line: keyLines[`${keyPath}.url`] ?? null,
      api: masked,
    });
  }

  const skill: Skill = {
    name,
    dir: path.dirname(configPath),
    manifestPath: configPath,
    capabilities: {
      shellExec,
      fileSystemAccess,
      fileSystemScoped,
      networkAccess,
      destructiveKeywords: [],
      dynamicEval: false,
      dataFlowToShellExec: false,
      evidence,
    },
    provenance: {
      sourceUrl: launch.kind === 'remote' ? launch.url : null,
      pinnedRef: detectPinnedRef(server),
      author: null,
    },
    // No separate manifest/lockfile concept for an MCP server entry —
    // the MCP config itself is already the provenance signal above, so
    // CHAP-SUP-002/003/006 (npm-manifest-shaped checks) correctly stay
    // silent rather than being forced onto a shape they don't fit.
    dependencies: {
      ecosystem: null,
      manifestPath: null,
      lockfilePath: null,
      names: [],
      versionsByName: {},
    },
    installScripts: { scripts: installScripts },
    confirmationRequired: null,
    domainAllowlist: null,
    launch,
  };
  return { skill, container };
}
