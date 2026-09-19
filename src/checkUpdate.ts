import { compareVersions } from './checks/shared/semver.js';
import { VERSION } from './version.js';

// Opt-in update check (improvement_plan.md 3.15/Phase 24) — the plan's
// own lowest-conviction item ("worth revisiting only if there's a clear
// user need"), built on explicit user confirmation. `chaperone
// check-update` is a SEPARATE, manually-invoked command, never run
// implicitly during `scan` (or any other command) and never on by
// default — the one deliberate, narrowly-scoped exception to the
// "no network" guarantee `chaperone scan` itself holds absolutely (see
// README's Security & ethics section). A real, timed-out-bounded
// network call, injectable for tests so `npm test` never makes a real
// one.

const REGISTRY_URL = 'https://registry.npmjs.org/@alpay_altuntas%2Fchaperone/latest';
const FETCH_TIMEOUT_MS = 5000;

export interface UpdateCheckResult {
  currentVersion: string;
  /** null when the check itself failed (network error, non-2xx, unexpected response shape) — see `error`. */
  latestVersion: string | null;
  updateAvailable: boolean;
  error: string | null;
}

interface NpmRegistryVersionResponse {
  version?: unknown;
}

function isNpmRegistryVersionResponse(value: unknown): value is NpmRegistryVersionResponse {
  return typeof value === 'object' && value !== null;
}

/**
 * Queries the npm registry's `/latest` dist-tag endpoint for the
 * currently-published version and compares it against this build's own
 * `VERSION`. `fetchImpl` is injectable (default: the real global
 * `fetch`) so tests can supply a mock — this is the one place in the
 * whole codebase a network call is even possible, and it must never run
 * during `npm test` for real.
 */
export async function checkForUpdate(fetchImpl: typeof fetch = fetch): Promise<UpdateCheckResult> {
  try {
    const response = await fetchImpl(REGISTRY_URL, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!response.ok) {
      return {
        currentVersion: VERSION,
        latestVersion: null,
        updateAvailable: false,
        error: `npm registry responded with HTTP ${String(response.status)}`,
      };
    }
    const data: unknown = await response.json();
    if (!isNpmRegistryVersionResponse(data) || typeof data.version !== 'string') {
      return {
        currentVersion: VERSION,
        latestVersion: null,
        updateAvailable: false,
        error: 'unexpected response shape from the npm registry',
      };
    }
    return {
      currentVersion: VERSION,
      latestVersion: data.version,
      updateAvailable: compareVersions(VERSION, data.version) < 0,
      error: null,
    };
  } catch (err) {
    return {
      currentVersion: VERSION,
      latestVersion: null,
      updateAvailable: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/** Renders the result as the one or two lines `chaperone check-update` prints. */
export function renderUpdateCheckResult(result: UpdateCheckResult): string {
  if (result.error !== null) {
    return `Could not check for updates: ${result.error}`;
  }
  if (result.updateAvailable) {
    return [
      `A newer version is available: v${result.latestVersion ?? '?'} (you have v${result.currentVersion}).`,
      'Run: npm install -g @alpay_altuntas/chaperone@latest',
    ].join('\n');
  }
  return `You're on the latest version (v${result.currentVersion}).`;
}
