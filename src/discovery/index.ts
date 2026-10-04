import { existsSync, readFileSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AgentModel, InspectedEntry, PermissionRole, SkippedEntry } from '../model/types.js';
import {
  CONFIG_FILENAMES,
  DEFAULT_ROOTS,
  locateConfigFile,
  probeDefaultRoot,
  resolveExplicitTarget,
} from './configLocator.js';
import { buildKeyLineIndex, maskConfig, parseConfigSource } from './configParser.js';
import { errorMessage } from './errors.js';
import { extractGatewayModel } from './gateway.js';
import { discoverClaudeCodeAgent } from './claudeCodeProfile.js';
import { discoverComposeContainers } from './containerPrivileges.js';
import { detectGitContext } from './gitContext.js';
import { getConfigField, isRecord } from './jsonUtils.js';
import { scanExistingLogContent } from './logContentScanner.js';
import { extractLoggingModel } from './logging.js';
import { discoverMcpAgent } from './mcpProfile.js';
import { extractMemoryModel } from './memory.js';
import { expandHome } from './pathUtils.js';
import { getFilePermissionFact } from './permissions.js';
import { detectRecoverability } from './recoverability.js';
import { discoverSidecarSecretFiles } from './sidecarSecrets.js';
import { scanSkills } from './skillsScanner.js';

/** 'default' (or unset) is the existing fictional Clawdbot/Moltbot/OpenClaw-style profile; 'mcp' is the real MCP server config profile (improvement_plan.md 3.1/Phase 17). */
export type DiscoveryProfile = 'default' | 'mcp' | 'claude-code';
export const DISCOVERY_PROFILES: readonly DiscoveryProfile[] = ['default', 'mcp', 'claude-code'];

export interface DiscoveryOptions {
  targetPath?: string;
  profile?: DiscoveryProfile;
}

export interface DiscoveryResult {
  model: AgentModel;
  targetRootResolved: boolean;
}

const DEFAULT_SKILLS_DIR = 'skills';

/** Orchestrates discovery: locates and parses agent artifacts into a normalized, defensively-built AgentModel. */
export function discoverAgent(options: DiscoveryOptions): DiscoveryResult {
  if (options.profile === 'mcp') {
    return discoverMcpAgent(options);
  }
  if (options.profile === 'claude-code') {
    return discoverClaudeCodeAgent(options);
  }

  const inspected: InspectedEntry[] = [];
  const skipped: SkippedEntry[] = [];

  if (options.targetPath !== undefined) {
    const explicit = resolveExplicitTarget(options.targetPath, CONFIG_FILENAMES);
    if (explicit.root === null) {
      const label = path.resolve(options.targetPath);
      skipped.push({ path: label, reason: explicit.reason });
      return { targetRootResolved: false, model: emptyModel(label, inspected, skipped) };
    }
    return discoverAtRoot(explicit.root, inspected, skipped);
  }

  const defaultRoot = probeDefaultRoot();
  if (defaultRoot === null) {
    // Specifically "no default install location exists", so the message
    // says so concretely rather than just "not found".
    const home = os.homedir();
    const triedRoots = DEFAULT_ROOTS.map((rel) => path.join(home, rel)).join(', ');
    const label = '(no default install location found)';
    skipped.push({
      path: label,
      reason: `no agent installation found at any default location (tried: ${triedRoots}). Pass an explicit path: chaperone scan <path>`,
    });
    return { targetRootResolved: false, model: emptyModel(label, inspected, skipped) };
  }
  return discoverAtRoot(defaultRoot, inspected, skipped);
}

function discoverAtRoot(
  targetRoot: string,
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): DiscoveryResult {
  const configPath = locateConfigFile(targetRoot);
  let rawParsed: unknown = null;
  let format: 'yaml' | 'json' | null = null;
  let configSource: string | null = null;

  if (configPath !== null) {
    try {
      const source = readFileSync(configPath, 'utf8');
      format = configPath.toLowerCase().endsWith('.json') ? 'json' : 'yaml';
      rawParsed = parseConfigSource(source, format);
      configSource = source;
      inspected.push({ path: configPath, kind: 'config' });
    } catch (err) {
      skipped.push({ path: configPath, reason: `unparseable config: ${errorMessage(err)}` });
    }
  } else {
    // A directory with neither a config file nor a skills directory isn't
    // an agent install. Running checks against its empty model would
    // report phantom findings and a passing grade for a CI path typo
    // (PROPOSED_FIXES.md 2.1), so it's reported as nothing scanned.
    if (!isDirectory(path.join(targetRoot, DEFAULT_SKILLS_DIR))) {
      skipped.push({
        path: targetRoot,
        reason: `no ${CONFIG_FILENAMES.join('/')} and no ${DEFAULT_SKILLS_DIR}/ directory found, so this doesn't look like an agent installation`,
      });
      return { targetRootResolved: false, model: emptyModel(targetRoot, inspected, skipped) };
    }
    skipped.push({ path: targetRoot, reason: 'no config.yaml/.yml/.json found in target root' });
  }

  // Gateway/logging facts must be derived from the RAW config, before
  // masking replaces literal secret-looking values (an empty/default auth
  // token is exactly the kind of literal masking would otherwise hide).
  const gateway = extractGatewayModel(rawParsed);
  let logging = extractLoggingModel(rawParsed, targetRoot);
  const memory = extractMemoryModel(rawParsed, targetRoot);
  const { data, secretFields: maskedSecretFields } = maskConfig(rawParsed);
  // Line numbers for every key (improvement_plan.md 1.17), YAML and JSON
  // alike (PROPOSED_FIXES.md 4.2).
  const keyLines = configSource !== null ? buildKeyLineIndex(configSource) : {};
  const secretFields = maskedSecretFields.map((field) => ({
    ...field,
    line: keyLines[field.keyPath] ?? null,
  }));

  const logPath = logging.path;
  if (logPath !== null && existsSync(logPath)) {
    const logScan = scanExistingLogContent(logPath);
    logging = { ...logging, existingSecretMatches: logScan.matches };
    inspected.push({ path: logPath, kind: 'log-file' });
    if (logScan.skippedReason !== null) {
      skipped.push({ path: logPath, reason: logScan.skippedReason });
    }
  }

  const sidecarResult = discoverSidecarSecretFiles(targetRoot);
  inspected.push(...sidecarResult.inspected);
  skipped.push(...sidecarResult.skipped);

  const git = detectGitContext(configPath ?? targetRoot, targetRoot);
  if (git.hasAncestorGitDir && git.gitDirPath !== null && git.gitRootPath !== null) {
    inspected.push({ path: git.gitDirPath, kind: 'other' });
    for (const gitignoreFile of git.gitignoreFiles) {
      const gitignorePath = path.join(
        git.gitRootPath,
        gitignoreFile.dirRelativeToRoot,
        '.gitignore',
      );
      inspected.push({ path: gitignorePath, kind: 'gitignore' });
    }
  }

  const skillsDirField = isRecord(rawParsed) ? getConfigField(rawParsed, 'skills_dir') : undefined;
  const configuredSkillsDir =
    typeof skillsDirField === 'string' ? skillsDirField : DEFAULT_SKILLS_DIR;
  const skillsDir = path.resolve(targetRoot, expandHome(configuredSkillsDir));

  const skillsResult = scanSkills(skillsDir);
  inspected.push(...skillsResult.inspected);
  skipped.push(...skillsResult.skipped);

  const permissionTargets: Array<[string | null, PermissionRole]> = [
    [configPath, 'config'],
    [logging.path, 'log'],
    [memory.dir, 'memory-dir'],
    ...sidecarResult.files.map((f): [string, PermissionRole] => [f.path, 'sidecar']),
    // Directories whose contents decide what the agent runs
    // (PROPOSED_FIXES.md 3.6, CHAP-SEC-008).
    [targetRoot, 'target-root'],
    [isDirectory(skillsDir) ? skillsDir : null, 'skills-dir'],
    ...skillsResult.skills.map((skill): [string, PermissionRole] => [skill.dir, 'skill-dir']),
  ];
  const permissions = permissionTargets
    .filter((entry): entry is [string, PermissionRole] => entry[0] !== null)
    .map(([p, role]) => getFilePermissionFact(p, role));

  const recoverability = detectRecoverability(targetRoot);

  // docker-compose services and their host privileges (CHAP-AGY-005).
  const compose = discoverComposeContainers(targetRoot);
  inspected.push(...compose.inspected);
  skipped.push(...compose.skipped);

  const model: AgentModel = {
    targetRoot,
    config: { path: configPath, format, data, secretFields, keyLines },
    sidecarSecretFiles: sidecarResult.files,
    git,
    permissions,
    skills: skillsResult.skills,
    containers: compose.containers,
    claudeCodeSettings: [],
    gateway,
    logging,
    memory,
    recoverability,
    inspected,
    skipped,
  };

  return { targetRootResolved: true, model };
}

function isDirectory(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** Shared by both profiles' "nothing found" paths (a missing default install, or a missing MCP config) — one canonical all-absent AgentModel shape. */
export function emptyModel(
  targetRootLabel: string,
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): AgentModel {
  return {
    targetRoot: targetRootLabel,
    config: { path: null, format: null, data: null, secretFields: [], keyLines: {} },
    sidecarSecretFiles: [],
    git: {
      hasAncestorGitDir: false,
      gitDirPath: null,
      gitRootPath: null,
      gitignoreFiles: [],
      configPathRelativeToGitRoot: null,
    },
    permissions: [],
    skills: [],
    containers: [],
    claudeCodeSettings: [],
    gateway: {
      present: false,
      bindHost: null,
      port: null,
      authConfigured: null,
      authTokenIsDefaultOrEmpty: null,
      authTokenWeakness: null,
      tlsEnabled: null,
    },
    logging: {
      present: false,
      level: null,
      path: null,
      redactSecrets: null,
      auditLogEnabled: null,
      existingSecretMatches: [],
    },
    memory: { present: false, dir: null },
    recoverability: { killSwitchDocumented: false },
    inspected,
    skipped,
  };
}
