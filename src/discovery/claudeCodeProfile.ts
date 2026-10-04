import { readFileSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type {
  AgentModel,
  ClaudeCodeSettingsFile,
  InspectedEntry,
  SkippedEntry,
} from '../model/types.js';
import { buildKeyLineIndex, maskConfig } from './configParser.js';
import { errorMessage } from './errors.js';
import { emptyModel, type DiscoveryOptions, type DiscoveryResult } from './index.js';
import { discoverMcpAgent } from './mcpProfile.js';
import { getFilePermissionFact } from './permissions.js';

// The Claude Code profile (PROPOSED_FIXES.md 6.1): Claude Code's own,
// public settings files, verified against the settings documentation
// (code.claude.com/docs/en/settings, /settings-reference, /permissions)
// on 2026-10-03. Managed settings (MDM, managed-settings.json) are an
// organization's policy rather than an install's configuration, so they
// aren't read.

type Scope = ClaudeCodeSettingsFile['scope'];

const PROJECT_SETTINGS: ReadonlyArray<{ relative: string; scope: Scope }> = [
  { relative: path.join('.claude', 'settings.json'), scope: 'project' },
  { relative: path.join('.claude', 'settings.local.json'), scope: 'local' },
];

function isFile(candidate: string): boolean {
  try {
    return statSync(candidate).isFile();
  } catch {
    return false;
  }
}

function isDirectory(candidate: string): boolean {
  try {
    return statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

/** The user-level settings file, read only when no path is given. */
export function userSettingsPath(home: string = os.homedir()): string {
  return path.join(home, '.claude', 'settings.json');
}

/** Which scope a settings file passed directly belongs to. */
function scopeForFile(file: string, home: string): Scope {
  if (path.basename(file) === 'settings.local.json') {
    return 'local';
  }
  return path.resolve(file) === userSettingsPath(home) ? 'user' : 'project';
}

/** The settings files a scan of `targetPath` (or, with none, the current directory plus the user's settings) reads. */
export function locateClaudeCodeSettings(
  targetPath: string | undefined,
  home: string = os.homedir(),
):
  { root: string; files: Array<{ path: string; scope: Scope }> } | { root: string; error: string } {
  const root = path.resolve(targetPath ?? process.cwd());
  if (targetPath !== undefined && isFile(root)) {
    return { root: path.dirname(root), files: [{ path: root, scope: scopeForFile(root, home) }] };
  }
  if (targetPath !== undefined && !isDirectory(root)) {
    return { root, error: 'path does not exist' };
  }
  const files = PROJECT_SETTINGS.map(({ relative, scope }) => ({
    path: path.join(root, relative),
    scope,
  })).filter((f) => isFile(f.path));
  // `~/.claude` itself (holding settings.json) is the user scope.
  if (path.basename(root) === '.claude' && isFile(path.join(root, 'settings.json'))) {
    files.push({
      path: path.join(root, 'settings.json'),
      scope: scopeForFile(path.join(root, 'settings.json'), home),
    });
  }
  if (targetPath === undefined && isFile(userSettingsPath(home))) {
    files.push({ path: userSettingsPath(home), scope: 'user' });
  }
  return { root, files };
}

/** Discovers Claude Code settings (and the project's `.mcp.json`, via the MCP profile's analysis). */
export function discoverClaudeCodeAgent(options: DiscoveryOptions): DiscoveryResult {
  const inspected: InspectedEntry[] = [];
  const skipped: SkippedEntry[] = [];

  const located = locateClaudeCodeSettings(options.targetPath);
  if ('error' in located) {
    skipped.push({ path: located.root, reason: located.error });
    return { targetRootResolved: false, model: emptyModel(located.root, inspected, skipped) };
  }

  const settings: ClaudeCodeSettingsFile[] = [];
  for (const file of located.files) {
    try {
      const source = readFileSync(file.path, 'utf8');
      const masked = maskConfig(JSON.parse(source) as unknown);
      const keyLines = buildKeyLineIndex(source, 'json');
      settings.push({
        path: file.path,
        scope: file.scope,
        data: masked.data,
        secretFields: masked.secretFields.map((field) => ({
          ...field,
          line: keyLines[field.keyPath] ?? null,
        })),
        keyLines,
      });
      inspected.push({ path: file.path, kind: 'config' });
    } catch (err) {
      skipped.push({
        path: file.path,
        reason: `unparseable Claude Code settings: ${errorMessage(err)}`,
      });
    }
  }

  // The project's .mcp.json is part of a Claude Code install; reuse the
  // MCP profile's server analysis for it (PROPOSED_FIXES.md 3.9).
  const mcp = discoverMcpAgent({ targetPath: located.root });
  const mcpModel: AgentModel | null = mcp.targetRootResolved ? mcp.model : null;

  if (settings.length === 0 && mcpModel === null) {
    skipped.push({
      path: located.root,
      reason: `no Claude Code settings found (tried: ${PROJECT_SETTINGS.map((s) => s.relative).join(', ')}${options.targetPath === undefined ? `, ${userSettingsPath()}` : ''}) and no .mcp.json`,
    });
    return { targetRootResolved: false, model: emptyModel(located.root, inspected, skipped) };
  }

  const base = mcpModel ?? emptyModel(located.root, [], []);
  const model: AgentModel = {
    ...base,
    targetRoot: located.root,
    claudeCodeSettings: settings,
    permissions: [
      ...base.permissions,
      ...settings.map((file) => getFilePermissionFact(file.path, 'config')),
    ],
    inspected: [...inspected, ...base.inspected],
    skipped: [...skipped, ...base.skipped],
  };
  return { targetRootResolved: true, model };
}
