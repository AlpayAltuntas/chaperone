import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SEC-003';
const TITLE = 'Overly permissive file permissions';
const OWASP = 'LLM06: Sensitive Information Disclosure';

/** Flags the config file when its POSIX mode is readable by group or other (broader than 0600). */
export const chapSec003PermissiveFilePermissions: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'secrets',
  owasp: OWASP,
  detects: 'The config file being readable by group or other.',
  heuristic:
    'POSIX file mode broader than `0600` (i.e. any group/other read bit set). Meaningful on macOS/Linux; not a reliable signal on platforms without POSIX permission bits.',
  remediation: '`chmod 600` the config file (and `chmod 700` its directory).',
  run(model) {
    if (model.config.path === null) {
      return [];
    }
    const fact = model.permissions.find((p) => p.path === model.config.path);
    if (fact === undefined || !fact.exists || fact.groupOrOtherReadable !== true) {
      return [];
    }

    const modeOctal = fact.mode !== null ? fact.mode.toString(8).padStart(3, '0') : 'unknown';
    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'secrets',
        owasp: OWASP,
        message: `The config file is readable by group or other (mode ${modeOctal}), so other local users/processes can read any secrets it holds.`,
        location: { filePath: model.config.path, line: null, detail: `mode ${modeOctal}` },
        remediation:
          'Restrict the file to owner-only access, e.g. `chmod 600` the config file (and `chmod 700` its directory).',
      },
    ];
  },
};
