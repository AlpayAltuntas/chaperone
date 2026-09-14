import { existsSync } from 'node:fs';
import path from 'node:path';
import type { RecoverabilityModel } from '../model/types.js';

// Documented convention for CHAP-OBS-003: a file at the install root naming
// a kill switch / revocation procedure. No real spec exists for this (same
// caveat as the config/manifest conventions in DECISIONS.md) — an install
// documenting this any other way won't be detected in v1.
const KILL_SWITCH_FILENAMES = ['KILL_SWITCH.md', 'STOP.md', 'kill-switch.sh', 'revoke.sh'];

/** Checks the target root for a file matching a known kill-switch-documentation naming convention. */
export function detectRecoverability(targetRoot: string): RecoverabilityModel {
  const killSwitchDocumented = KILL_SWITCH_FILENAMES.some((filename) =>
    existsSync(path.join(targetRoot, filename)),
  );
  return { killSwitchDocumented };
}
