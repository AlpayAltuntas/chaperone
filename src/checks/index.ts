import type { Check } from '../engine/types.js';
import { chapAgy001UnrestrictedShell } from './agency/chapAgy001UnrestrictedShell.js';
import { chapNet001GatewayExposed } from './network/chapNet001GatewayExposed.js';
import { chapSec001PlaintextSecrets } from './secrets/chapSec001PlaintextSecrets.js';

// Extending Chaperone with a new check means adding one module under
// src/checks/<category>/ and registering it here — the engine itself
// never changes.
export const ALL_CHECKS: readonly Check[] = [
  chapSec001PlaintextSecrets,
  chapAgy001UnrestrictedShell,
  chapNet001GatewayExposed,
];
