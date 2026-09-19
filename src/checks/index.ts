import type { Check } from '../engine/types.js';
import { chapAgy001UnrestrictedShell } from './agency/chapAgy001UnrestrictedShell.js';
import { chapAgy002UnrestrictedFilesystem } from './agency/chapAgy002UnrestrictedFilesystem.js';
import { chapAgy003DestructiveWithoutConfirmation } from './agency/chapAgy003DestructiveWithoutConfirmation.js';
import { chapAgy004BroadNetworkEgress } from './agency/chapAgy004BroadNetworkEgress.js';
import { chapInj001UntrustedInputUnmarked } from './injection/chapInj001UntrustedInputUnmarked.js';
import { chapInj002ToolOutputTrusted } from './injection/chapInj002ToolOutputTrusted.js';
import { chapInj003NoToolAllowlist } from './injection/chapInj003NoToolAllowlist.js';
import { chapInj004AutoExecuteFromMessages } from './injection/chapInj004AutoExecuteFromMessages.js';
import { chapInj005ChannelTrustLevel } from './injection/chapInj005ChannelTrustLevel.js';
import { chapNet001GatewayExposed } from './network/chapNet001GatewayExposed.js';
import { chapNet002WeakGatewayAuth } from './network/chapNet002WeakGatewayAuth.js';
import { chapNet003PlaintextTransport } from './network/chapNet003PlaintextTransport.js';
import { chapObs001NoAuditLog } from './observability/chapObs001NoAuditLog.js';
import { chapObs002UnredactedLogs } from './observability/chapObs002UnredactedLogs.js';
import { chapObs003NoKillSwitch } from './observability/chapObs003NoKillSwitch.js';
import { chapObs004MemoryStoreExposed } from './observability/chapObs004MemoryStoreExposed.js';
import { chapSec001PlaintextSecrets } from './secrets/chapSec001PlaintextSecrets.js';
import { chapSec002GitTrackedSecrets } from './secrets/chapSec002GitTrackedSecrets.js';
import { chapSec003PermissiveFilePermissions } from './secrets/chapSec003PermissiveFilePermissions.js';
import { chapSec004SecretsReachLogs } from './secrets/chapSec004SecretsReachLogs.js';
import { chapSec005SecretsInExistingLogs } from './secrets/chapSec005SecretsInExistingLogs.js';
import { chapSec006SidecarSecretFileExposed } from './secrets/chapSec006SidecarSecretFileExposed.js';
import { chapSec007EnvVarNotSet } from './secrets/chapSec007EnvVarNotSet.js';
import { chapSup001UnverifiedSources } from './supplyChain/chapSup001UnverifiedSources.js';
import { chapSup002NoIntegrityVerification } from './supplyChain/chapSup002NoIntegrityVerification.js';
import { chapSup003KnownVulnerableDependencies } from './supplyChain/chapSup003KnownVulnerableDependencies.js';
import { chapSup004DangerousInstallPatterns } from './supplyChain/chapSup004DangerousInstallPatterns.js';
import { chapSup005ObfuscatedCode } from './supplyChain/chapSup005ObfuscatedCode.js';
import { chapSup006TyposquatRisk } from './supplyChain/chapSup006TyposquatRisk.js';

// Extending Chaperone with a new check means adding one module under
// src/checks/<category>/ and registering it here — the engine itself
// never changes.
export const ALL_CHECKS: readonly Check[] = [
  // Secrets & credential hygiene
  chapSec001PlaintextSecrets,
  chapSec002GitTrackedSecrets,
  chapSec003PermissiveFilePermissions,
  chapSec004SecretsReachLogs,
  chapSec005SecretsInExistingLogs,
  chapSec006SidecarSecretFileExposed,
  chapSec007EnvVarNotSet,
  // Excessive agency & permissions
  chapAgy001UnrestrictedShell,
  chapAgy002UnrestrictedFilesystem,
  chapAgy003DestructiveWithoutConfirmation,
  chapAgy004BroadNetworkEgress,
  // Supply chain & skill provenance
  chapSup001UnverifiedSources,
  chapSup002NoIntegrityVerification,
  chapSup003KnownVulnerableDependencies,
  chapSup004DangerousInstallPatterns,
  chapSup005ObfuscatedCode,
  chapSup006TyposquatRisk,
  // Prompt-injection surface
  chapInj001UntrustedInputUnmarked,
  chapInj002ToolOutputTrusted,
  chapInj003NoToolAllowlist,
  chapInj004AutoExecuteFromMessages,
  chapInj005ChannelTrustLevel,
  // Exposure & network posture
  chapNet001GatewayExposed,
  chapNet002WeakGatewayAuth,
  chapNet003PlaintextTransport,
  // Observability & recoverability
  chapObs001NoAuditLog,
  chapObs002UnredactedLogs,
  chapObs003NoKillSwitch,
  chapObs004MemoryStoreExposed,
];
