import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { AgentModel, InspectedEntry, SkippedEntry } from '../model/types.js';
import { locateConfigFile, resolveTargetRoot } from './configLocator.js';
import { maskConfig, parseConfigSource } from './configParser.js';
import { errorMessage } from './errors.js';
import { extractGatewayModel } from './gateway.js';
import { detectGitContext } from './gitContext.js';
import { isRecord } from './jsonUtils.js';
import { extractLoggingModel } from './logging.js';
import { getFilePermissionFact } from './permissions.js';
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
    const label = options.targetPath ?? '(no default install location found)';
    skipped.push({
      path: label,
      reason: 'target root does not exist and no default install location was found',
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
  const logging = extractLoggingModel(rawParsed, targetRoot);
  const { data, secretFields } = maskConfig(rawParsed);

  const git = detectGitContext(configPath ?? targetRoot);
  if (git.hasAncestorGitDir && git.gitDirPath !== null && git.gitRootPath !== null) {
    inspected.push({ path: git.gitDirPath, kind: 'other' });
    const gitignorePath = path.join(git.gitRootPath, '.gitignore');
    if (existsSync(gitignorePath)) {
      inspected.push({ path: gitignorePath, kind: 'gitignore' });
    }
  }

  const permissionTargets = [configPath, logging.path].filter((p): p is string => p !== null);
  const permissions = permissionTargets.map((p) => getFilePermissionFact(p));

  const configuredSkillsDir =
    isRecord(rawParsed) && typeof rawParsed['skills_dir'] === 'string'
      ? rawParsed['skills_dir']
      : 'skills';
  const skillsDir = path.resolve(targetRoot, configuredSkillsDir);
  const skillsResult = scanSkills(skillsDir);
  inspected.push(...skillsResult.inspected);
  skipped.push(...skillsResult.skipped);

  const model: AgentModel = {
    targetRoot,
    config: { path: configPath, format, data, secretFields },
    git,
    permissions,
    skills: skillsResult.skills,
    gateway,
    logging,
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
    git: {
      hasAncestorGitDir: false,
      gitDirPath: null,
      gitRootPath: null,
      gitignorePatterns: [],
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
    },
    inspected,
    skipped,
  };
}
