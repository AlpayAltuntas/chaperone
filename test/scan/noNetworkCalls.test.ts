import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { run } from '../../src/cli.js';

// improvement_plan.md 1.15/Phase 18's DoD, verbatim: "no network call
// happens during `chaperone scan`, verified by a test that fails if one
// occurs." CHAP-SUP-003 is the check most at risk of regressing this —
// it's the one check with a real, live counterpart (OSV.dev) it could
// plausibly be tempted to call directly instead of reading the bundled
// offline snapshot (shared/vulnDb.ts) — but this test isn't scoped to
// that one check: it spies on every network primitive Node exposes and
// runs a full scan, so *any* check (present or future) making an
// outbound call would fail it, not just this one.
describe('chaperone scan — no network calls (improvement_plan.md 1.15/Phase 18)', () => {
  let logSpy: MockInstance<typeof console.log>;
  let fetchSpy: MockInstance<typeof fetch>;
  let httpRequestSpy: MockInstance<typeof http.request>;
  let httpGetSpy: MockInstance<typeof http.get>;
  let httpsRequestSpy: MockInstance<typeof https.request>;
  let httpsGetSpy: MockInstance<typeof https.get>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const networkCallError = (): never => {
      throw new Error('unexpected outbound network call during chaperone scan');
    };
    fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(networkCallError);
    httpRequestSpy = vi.spyOn(http, 'request').mockImplementation(networkCallError);
    httpGetSpy = vi.spyOn(http, 'get').mockImplementation(networkCallError);
    httpsRequestSpy = vi.spyOn(https, 'request').mockImplementation(networkCallError);
    httpsGetSpy = vi.spyOn(https, 'get').mockImplementation(networkCallError);
  });

  afterEach(() => {
    logSpy.mockRestore();
    fetchSpy.mockRestore();
    httpRequestSpy.mockRestore();
    httpGetSpy.mockRestore();
    httpsRequestSpy.mockRestore();
    httpsGetSpy.mockRestore();
  });

  it('scanning the vulnerable fixture (which trips CHAP-SUP-003, the check closest to a real network dependency) makes zero outbound calls', () => {
    expect(() => {
      run([
        'node',
        'chaperone',
        'scan',
        path.join('test', 'fixtures', 'vulnerable-agent'),
        '--format',
        'json',
      ]);
    }).not.toThrow();

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(httpRequestSpy).not.toHaveBeenCalled();
    expect(httpGetSpy).not.toHaveBeenCalled();
    expect(httpsRequestSpy).not.toHaveBeenCalled();
    expect(httpsGetSpy).not.toHaveBeenCalled();

    // Sanity check that the scan actually ran (not a vacuous pass from
    // an early exit) and that CHAP-SUP-003 really did produce its
    // real-match finding entirely offline.
    const printed = logSpy.mock.calls[0]?.[0] as string;
    const report = JSON.parse(printed) as { findings: Array<{ checkId: string }> };
    expect(report.findings.some((f) => f.checkId === 'CHAP-SUP-003')).toBe(true);
  });

  it('scanning the mcp profile fixture also makes zero outbound calls', () => {
    run([
      'node',
      'chaperone',
      'scan',
      path.join('test', 'fixtures', 'mcp-vulnerable'),
      '--profile',
      'mcp',
      '--format',
      'json',
    ]);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(httpRequestSpy).not.toHaveBeenCalled();
    expect(httpGetSpy).not.toHaveBeenCalled();
    expect(httpsRequestSpy).not.toHaveBeenCalled();
    expect(httpsGetSpy).not.toHaveBeenCalled();
  });
});
