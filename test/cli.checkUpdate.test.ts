import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../src/cli.js';
import { VERSION } from '../src/version.js';

// improvement_plan.md 3.15/Phase 24 (chaperone check-update). The
// action is async (a real network call can't be synchronous) while
// `run()` itself stays synchronous (program.parse(), not
// parseAsync() — see DECISIONS.md, Phase 24, for why) — so this test
// waits for the fire-and-forget promise to settle via vi.waitFor,
// rather than asserting immediately after run() returns the way every
// other (fully synchronous) cli.*.test.ts file can. fetch is mocked
// globally so this never makes a real network call.
describe('cli check-update (mocked fetch, no real network call)', () => {
  let logSpy: MockInstance<typeof console.log>;
  let fetchSpy: MockInstance<typeof fetch>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
    fetchSpy.mockRestore();
  });

  it('prints an up-to-date message when the registry reports the same version', async () => {
    fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(JSON.stringify({ version: VERSION }), { status: 200 }));

    run(['node', 'chaperone', 'check-update']);

    await vi.waitFor(() => {
      expect(logSpy).toHaveBeenCalled();
    });
    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('latest version');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('prints an update-available message when the registry reports a newer version', async () => {
    fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(JSON.stringify({ version: '99.0.0' }), { status: 200 }));

    run(['node', 'chaperone', 'check-update']);

    await vi.waitFor(() => {
      expect(logSpy).toHaveBeenCalled();
    });
    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('A newer version is available: v99.0.0');
  });

  it('prints a clear error message, without throwing, when the network call fails', async () => {
    fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network unreachable'));

    expect(() => {
      run(['node', 'chaperone', 'check-update']);
    }).not.toThrow();

    await vi.waitFor(() => {
      expect(logSpy).toHaveBeenCalled();
    });
    const printed = logSpy.mock.calls[0]?.[0] as string;
    expect(printed).toContain('Could not check for updates');
  });
});

describe('cli scan — never triggers a check-update-style fetch call', () => {
  it('does not call fetch at all during an ordinary scan', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('unexpected fetch call during scan');
    });
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);

    try {
      run(['node', 'chaperone', 'scan', 'test/fixtures/clean-agent', '--format', 'json']);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
      logSpy.mockRestore();
    }
  });
});
