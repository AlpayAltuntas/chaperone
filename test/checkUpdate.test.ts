import { describe, expect, it } from 'vitest';
import { checkForUpdate, renderUpdateCheckResult } from '../src/checkUpdate.js';
import { VERSION } from '../src/version.js';

// improvement_plan.md 3.15/Phase 24 — checkForUpdate's fetchImpl is
// injectable specifically so this file never makes a real network call:
// npm test must stay fully offline and deterministic, per this
// project's own "no network" posture everywhere except this one,
// explicitly opt-in command. A real registry call was verified manually
// once instead — see DECISIONS.md, Phase 24.

function mockFetch(body: unknown, status = 200): typeof fetch {
  return () =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      }),
    );
}

describe('checkForUpdate', () => {
  it('reports no update available when the registry version matches VERSION', async () => {
    const result = await checkForUpdate(mockFetch({ version: VERSION }));

    expect(result).toEqual({
      currentVersion: VERSION,
      latestVersion: VERSION,
      updateAvailable: false,
      error: null,
    });
  });

  it('reports an update available when the registry version is newer', async () => {
    const result = await checkForUpdate(mockFetch({ version: '99.0.0' }));

    expect(result.updateAvailable).toBe(true);
    expect(result.latestVersion).toBe('99.0.0');
    expect(result.error).toBeNull();
  });

  it('does not report an update when the registry version is OLDER than VERSION', async () => {
    const result = await checkForUpdate(mockFetch({ version: '0.0.1' }));

    expect(result.updateAvailable).toBe(false);
    expect(result.error).toBeNull();
  });

  it('reports a clear error for a non-2xx registry response, without a latestVersion', async () => {
    const result = await checkForUpdate(mockFetch({}, 404));

    expect(result.latestVersion).toBeNull();
    expect(result.updateAvailable).toBe(false);
    expect(result.error).toContain('404');
  });

  it('reports a clear error for an unexpected response shape', async () => {
    const result = await checkForUpdate(mockFetch({ notAVersionField: true }));

    expect(result.latestVersion).toBeNull();
    expect(result.error).toContain('unexpected response shape');
  });

  it('reports a clear error when the fetch itself throws (network failure, timeout, ...)', async () => {
    const throwingFetch = (() =>
      Promise.reject(new Error('getaddrinfo ENOTFOUND registry.npmjs.org'))) as typeof fetch;

    const result = await checkForUpdate(throwingFetch);

    expect(result.latestVersion).toBeNull();
    expect(result.updateAvailable).toBe(false);
    expect(result.error).toContain('ENOTFOUND');
  });
});

describe('renderUpdateCheckResult', () => {
  it('renders the error message when the check failed', () => {
    const text = renderUpdateCheckResult({
      currentVersion: '1.0.0',
      latestVersion: null,
      updateAvailable: false,
      error: 'network unreachable',
    });

    expect(text).toBe('Could not check for updates: network unreachable');
  });

  it('renders an update-available message with the install command', () => {
    const text = renderUpdateCheckResult({
      currentVersion: '1.0.0',
      latestVersion: '1.2.0',
      updateAvailable: true,
      error: null,
    });

    expect(text).toContain('A newer version is available: v1.2.0 (you have v1.0.0).');
    expect(text).toContain('npm install -g @alpay_altuntas/chaperone@latest');
  });

  it('renders an up-to-date message', () => {
    const text = renderUpdateCheckResult({
      currentVersion: '1.0.0',
      latestVersion: '1.0.0',
      updateAvailable: false,
      error: null,
    });

    expect(text).toBe("You're on the latest version (v1.0.0).");
  });
});
