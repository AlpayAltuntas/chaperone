import { readFileSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import type { ContainerLaunch, InspectedEntry, SkippedEntry } from '../model/types.js';
import { buildKeyLineIndex } from './configParser.js';
import { errorMessage } from './errors.js';
import { isRecord } from './jsonUtils.js';

// Host-level container privileges (PROPOSED_FIXES.md 3.9, CHAP-AGY-005):
// anything that lets code in the container act on the host. A container
// with these is no sandbox at all for the agent or tool running in it.

// Bind-mount sources that hand the container the host: the whole disk,
// the Docker socket (root on the host), or the user's home directory.
const DANGEROUS_MOUNT_SOURCES = new Set([
  '/',
  '/var/run/docker.sock',
  '/run/docker.sock',
  '~',
  '$HOME',
  '${HOME}',
]);

const DANGEROUS_CAPABILITIES = new Set(['ALL', 'SYS_ADMIN']);

export const COMPOSE_FILENAMES = [
  'docker-compose.yml',
  'docker-compose.yaml',
  'compose.yml',
  'compose.yaml',
];

function normalizeMountSource(source: string): string {
  const trimmed = source.trim();
  return trimmed.length > 1 ? trimmed.replace(/\/+$/, '') : trimmed;
}

function mountPrivilege(source: string): string | null {
  const normalized = normalizeMountSource(source);
  return DANGEROUS_MOUNT_SOURCES.has(normalized) ? `bind mount of ${normalized}` : null;
}

/** `src:dst[:mode]` -> src, for `-v`/`--volume` and short compose syntax. */
function volumeSource(spec: string): string {
  const colon = spec.indexOf(':');
  return colon === -1 ? spec : spec.slice(0, colon);
}

/** `type=bind,source=/,target=/host` -> '/' (also `src=`). */
function mountFlagSource(spec: string): string | null {
  for (const part of spec.split(',')) {
    const [key, value] = part.split('=');
    if ((key === 'source' || key === 'src') && value !== undefined) {
      return value;
    }
  }
  return null;
}

/**
 * Host privileges granted by a `docker run`/`podman run` argument list
 * (`command` is the binary, `args` everything after it). Returns null
 * when the command isn't a container run at all.
 */
export function containerRunPrivileges(command: string, args: readonly string[]): string[] | null {
  const binary = path.basename(command).replace(/\.exe$/i, '');
  if ((binary !== 'docker' && binary !== 'podman') || !args.includes('run')) {
    return null;
  }
  const privileges: string[] = [];
  const runArgs = args.slice(args.indexOf('run') + 1);
  for (let i = 0; i < runArgs.length; i++) {
    const arg = runArgs[i] ?? '';
    const [flag, inlineValue] = arg.includes('=')
      ? [arg.slice(0, arg.indexOf('=')), arg.slice(arg.indexOf('=') + 1)]
      : [arg, undefined];
    const value = (): string => inlineValue ?? runArgs[++i] ?? '';
    switch (flag) {
      case '--privileged':
        privileges.push('--privileged');
        break;
      case '--cap-add': {
        const cap = value().toUpperCase();
        if (DANGEROUS_CAPABILITIES.has(cap)) {
          privileges.push(`--cap-add=${cap}`);
        }
        break;
      }
      case '--pid':
      case '--network':
      case '--net':
      case '--ipc':
      case '--userns': {
        const mode = value();
        if (mode === 'host') {
          privileges.push(`${flag}=host`);
        }
        break;
      }
      case '-v':
      case '--volume': {
        const privilege = mountPrivilege(volumeSource(value()));
        if (privilege !== null) {
          privileges.push(privilege);
        }
        break;
      }
      case '--mount': {
        const source = mountFlagSource(value());
        const privilege = source === null ? null : mountPrivilege(source);
        if (privilege !== null) {
          privileges.push(privilege);
        }
        break;
      }
      default:
        // The first non-flag argument is the image; everything after it
        // belongs to the container's own command.
        if (!arg.startsWith('-')) {
          return privileges;
        }
    }
  }
  return privileges;
}

function composeServicePrivileges(service: Record<string, unknown>): string[] {
  const privileges: string[] = [];
  if (service['privileged'] === true) {
    privileges.push('privileged: true');
  }
  const capAdd = service['cap_add'];
  if (Array.isArray(capAdd)) {
    for (const cap of capAdd) {
      if (typeof cap === 'string' && DANGEROUS_CAPABILITIES.has(cap.toUpperCase())) {
        privileges.push(`cap_add: ${cap.toUpperCase()}`);
      }
    }
  }
  for (const key of ['pid', 'network_mode', 'ipc', 'userns_mode']) {
    if (service[key] === 'host') {
      privileges.push(`${key}: host`);
    }
  }
  const volumes = service['volumes'];
  if (Array.isArray(volumes)) {
    for (const volume of volumes) {
      const source =
        typeof volume === 'string'
          ? volumeSource(volume)
          : isRecord(volume) && typeof volume['source'] === 'string'
            ? volume['source']
            : null;
      const privilege = source === null ? null : mountPrivilege(source);
      if (privilege !== null) {
        privileges.push(privilege);
      }
    }
  }
  return privileges;
}

export interface ComposeDiscoveryResult {
  containers: ContainerLaunch[];
  inspected: InspectedEntry[];
  skipped: SkippedEntry[];
}

/** Reads docker-compose/compose files in the target root and reports each service's host privileges. */
export function discoverComposeContainers(targetRoot: string): ComposeDiscoveryResult {
  const containers: ContainerLaunch[] = [];
  const inspected: InspectedEntry[] = [];
  const skipped: SkippedEntry[] = [];
  for (const filename of COMPOSE_FILENAMES) {
    const file = path.join(targetRoot, filename);
    let source: string;
    try {
      source = readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    let parsed: unknown;
    try {
      parsed = YAML.parse(source) as unknown;
    } catch (err) {
      skipped.push({ path: file, reason: `unparseable compose file: ${errorMessage(err)}` });
      continue;
    }
    inspected.push({ path: file, kind: 'config' });
    const services = isRecord(parsed) && isRecord(parsed['services']) ? parsed['services'] : {};
    const keyLines = buildKeyLineIndex(source);
    for (const [name, service] of Object.entries(services)) {
      if (!isRecord(service)) {
        continue;
      }
      const hostPrivileges = composeServicePrivileges(service);
      if (hostPrivileges.length > 0) {
        containers.push({
          name,
          source: file,
          line: keyLines[`services.${name}`] ?? null,
          hostPrivileges,
        });
      }
    }
  }
  return { containers, inspected, skipped };
}
