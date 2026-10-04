import type { Check } from '../../engine/types.js';

const ID = 'CHAP-AGY-005';
const TITLE = 'Container launched with host-level privileges';
const OWASP = 'LLM08: Excessive Agency';
const REMEDIATION =
  'Drop the host-level options: no --privileged, no --cap-add=ALL/SYS_ADMIN, no host PID/network/IPC namespaces, and no bind mounts of /, the Docker socket, or the home directory. Mount only the specific directories the tool needs, read-only where possible.';

/** Flags a container (an MCP server's `docker run`, or a compose service) granted host-level privileges (PROPOSED_FIXES.md 3.9). */
export const chapAgy005PrivilegedContainer: Check = {
  id: ID,
  title: TITLE,
  severity: 'critical',
  category: 'agency',
  owasp: OWASP,
  detects:
    'A container the agent or one of its tools runs in, configured so code inside it can act on the host: an MCP server launched with `docker run`/`podman run`, or a `docker-compose.yml`/`compose.yaml` service in the install directory.',
  heuristic:
    '`--privileged` / `privileged: true`; `--cap-add` of `ALL` or `SYS_ADMIN`; host PID, network, IPC, or user namespace (`--pid=host`, `network_mode: host`, ...); or a bind mount whose source is `/`, `/var/run/docker.sock`, `~`, or `$HOME`. Any one of these makes the container no sandbox: the Docker socket alone is root on the host.',
  remediation: REMEDIATION,
  run(model) {
    return model.containers.map((container) => ({
      checkId: ID,
      title: TITLE,
      severity: 'critical' as const,
      category: 'agency' as const,
      owasp: OWASP,
      message: `Container '${container.name}' is launched with host-level privileges (${container.hostPrivileges.join(', ')}), so anything running inside it can act on the host.`,
      location: { filePath: container.source, line: container.line, detail: container.name },
      remediation: REMEDIATION,
    }));
  },
};
