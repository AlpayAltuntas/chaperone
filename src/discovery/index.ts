import { existsSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AgentModel, InspectedEntry, SkippedEntry } from '../model/types.js';
import { DEFAULT_ROOTS, locateConfigFile, resolveTargetRoot } from './configLocator.js';
import { maskConfig, parseConfigSource } from './configParser.js';
import { errorMessage } from './errors.js';
import { extractGatewayModel } from './gateway.js';
import { detectGitContext } from './gitContext.js';
import { isRecord } from './jsonUtils.js';
import { scanExistingLogContent } from './logContentScanner.js';
import { extractLoggingModel } from './logging.js';
import { extractMemoryModel } from './memory.js';
import { expandHome } from './pathUtils.js';
import { getFilePermissionFact } from './permissions.js';
import { detectRecoverability } from './recoverability.js';
import { discoverSidecarSecretFiles } from './sidecarSecrets.js';
import { scanSkills } from './skillsScanner.js';

export interface DiscoveryOptions {
  targetPath?: string;
}

export interface DiscoveryResult {
  model: AgentModel;
  targetRootResolved: boolean;
}

/** Orchestrates discovery: locates and parses agent artifacts into a normalized, defensively-built AgentModel. */
export function discoverAgent(options: DiscoveryOptions): DiscoveryResult {
  const inspected: InspectedEntry[] = [];
  const skipped: SkippedEntry[] = [];

  const targetRoot = resolveTargetRoot(options.targetPath);
  if (targetRoot === null) {
    // resolveTargetRoot only returns null in the no-explicit-path case (an
    // explicit path always resolves to *some* absolute path, even a
    // nonexistent one) — so this is specifically "no default install
    // location exists", and the message says so concretely rather than
    // just "not found".
    const home = os.homedir();
    const triedRoots = DEFAULT_ROOTS.map((rel) => path.join(home, rel)).join(', ');
    const label = '(no default install location found)';
    skipped.push({
      path: label,
      reason: `no agent installation found at any default location (tried: ${triedRoots}). Pass an explicit path: chaperone scan <path>`,
    });
    return { targetRootResolved: false, model: emptyModel(label, inspected, skipped) };
  }

  const configPath = locateConfigFile(targetRoot);
  let rawParsed: unknown = null;
  let format: 'yaml' | 'json' | null = null;

  if (configPath !== null) {
    try {
      const source = readFileSync(configPath, 'utf8');
      format = configPath.toLowerCase().endsWith('.json') ? 'json' : 'yaml';
      rawParsed = parseConfigSource(source, format);
      inspected.push({ path: configPath, kind: 'config' });
    } catch (err) {
      skipped.push({ path: configPath, reason: `unparseable config: ${errorMessage(err)}` });
    }
  } else {
    skipped.push({ path: targetRoot, reason: 'no config.yaml/.yml/.json found in target root' });
  }

  // Gateway/logging facts must be derived from the RAW config, before
  // masking replaces literal secret-looking values (an empty/default auth
  // token is exactly the kind of literal masking would otherwise hide).
  const gateway = extractGatewayModel(rawParsed);
  let logging = extractLoggingModel(rawParsed, targetRoot);
  const memory = extractMemoryModel(rawParsed, targetRoot);
  const { data, secretFields } = maskConfig(rawParsed);

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

  const permissionTargets = [
    configPath,
    logging.path,
    memory.dir,
    ...sidecarResult.files.map((f) => f.path),
  ].filter((p): p is string => p !== null);
  const permissions = permissionTargets.map((p) => getFilePermissionFact(p));

  const configuredSkillsDir =
    isRecord(rawParsed) && typeof rawParsed['skills_dir'] === 'string'
      ? rawParsed['skills_dir']
      : 'skills';
  const skillsDir = path.resolve(targetRoot, expandHome(configuredSkillsDir));
  const skillsResult = scanSkills(skillsDir);
  inspected.push(...skillsResult.inspected);
  skipped.push(...skillsResult.skipped);

  const recoverability = detectRecoverability(targetRoot);

  const model: AgentModel = {
    targetRoot,
    config: { path: configPath, format, data, secretFields },
    sidecarSecretFiles: sidecarResult.files,
    git,
    permissions,
    skills: skillsResult.skills,
    gateway,
    logging,
    memory,
    recoverability,
    inspected,
    skipped,
  };

  return { targetRootResolved: true, model };
}

function emptyModel(
  targetRootLabel: string,
  inspected: InspectedEntry[],
  skipped: SkippedEntry[],
): AgentModel {
  return {
    targetRoot: targetRootLabel,
    config: { path: null, format: null, data: null, secretFields: [] },
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
    gateway: {
      present: false,
      bindHost: null,
      port: null,
      authConfigured: null,
      authTokenIsDefaultOrEmpty: null,
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
