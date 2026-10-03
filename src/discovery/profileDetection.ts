import { statSync } from 'node:fs';
import path from 'node:path';
import { CONFIG_FILENAMES, probeDefaultRoot } from './configLocator.js';
import type { DiscoveryProfile } from './index.js';
import { MCP_CONFIG_FILENAMES } from './mcpProfile.js';

// Profile auto-detection (PROPOSED_FIXES.md 6.3), used when --profile
// isn't given. Only project-level files count: a user-level MCP or
// Claude Code config exists on most developer machines and would match
// every scan.

const MCP_PROJECT_FILES = [
  ...MCP_CONFIG_FILENAMES,
  path.join('.vscode', 'mcp.json'),
  path.join('.cursor', 'mcp.json'),
];
const CLAUDE_CODE_FILES = [
  path.join('.claude', 'settings.json'),
  path.join('.claude', 'settings.local.json'),
];

function exists(p: string, kind: 'file' | 'dir'): boolean {
  try {
    const stat = statSync(p);
    return kind === 'file' ? stat.isFile() : stat.isDirectory();
  } catch {
    return false;
  }
}

export type ProfileDetection =
  | { profile: DiscoveryProfile; detected: boolean }
  | { error: string; candidates: DiscoveryProfile[] };

/** Which profiles' files a target holds. */
export function matchingProfiles(targetPath: string | undefined): DiscoveryProfile[] {
  const resolved = path.resolve(targetPath ?? process.cwd());
  if (targetPath !== undefined && exists(resolved, 'file')) {
    const name = path.basename(resolved);
    if (CONFIG_FILENAMES.includes(name)) {
      return ['default'];
    }
    if (path.basename(path.dirname(resolved)) === '.claude') {
      return ['claude-code'];
    }
    return name.endsWith('.json') ? ['mcp'] : [];
  }
  const root = targetPath === undefined ? probeDefaultRoot() : resolved;
  const matches: DiscoveryProfile[] = [];
  if (
    root !== null &&
    (CONFIG_FILENAMES.some((f) => exists(path.join(root, f), 'file')) ||
      exists(path.join(root, 'skills'), 'dir'))
  ) {
    matches.push('default');
  }
  // MCP and Claude Code files are project-scoped: with no path, look in
  // the current directory, not the default install root.
  const projectRoot = resolved;
  const hasMcp = MCP_PROJECT_FILES.some((f) => exists(path.join(projectRoot, f), 'file'));
  const hasClaudeCode = CLAUDE_CODE_FILES.some((f) => exists(path.join(projectRoot, f), 'file'));
  // The claude-code profile also analyzes .mcp.json, so it subsumes mcp.
  if (hasClaudeCode) {
    matches.push('claude-code');
  } else if (hasMcp) {
    matches.push('mcp');
  }
  return matches;
}

/** Picks the profile for a scan with no --profile: the one that matches, `default` when none does, or an error when several do. */
export function detectProfile(targetPath: string | undefined): ProfileDetection {
  const matches = matchingProfiles(targetPath);
  if (matches.length === 0) {
    return { profile: 'default', detected: false };
  }
  if (matches.length === 1) {
    const [profile] = matches;
    return { profile: profile ?? 'default', detected: true };
  }
  return {
    candidates: matches,
    error: `${targetPath ?? 'the current directory'} matches more than one discovery profile (${matches.join(', ')}). Pass --profile to choose one.`,
  };
}
