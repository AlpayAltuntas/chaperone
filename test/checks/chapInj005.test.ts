import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chapInj005ChannelTrustLevel } from '../../src/checks/injection/chapInj005ChannelTrustLevel.js';
import { discoverAgent } from '../../src/discovery/index.js';

const CONFIG_HEADER = 'llm:\n  provider: anthropic\n';

describe('CHAP-INJ-005 — inbound channels do not distinguish trust level', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'chaperone-inj005-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('fires when a public channel with no override and a private channel share the same non-empty global allowlist', () => {
    writeFileSync(
      path.join(dir, 'config.yaml'),
      `${CONFIG_HEADER}channels:\n  discord:\n    enabled: true\n    public: true\n  telegram_admin:\n    enabled: true\n    public: false\ntrust:\n  tool_allowlist:\n    - notes.writeNote\n`,
    );

    const { model } = discoverAgent({ targetPath: dir });
    const findings = chapInj005ChannelTrustLevel.run(model);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.checkId).toBe('CHAP-INJ-005');
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.message).toContain('discord');
  });

  it('treats a channel with no declared "public" field as public by default (same conservative default as CHAP-INJ-001)', () => {
    writeFileSync(
      path.join(dir, 'config.yaml'),
      `${CONFIG_HEADER}channels:\n  discord:\n    enabled: true\n  telegram_admin:\n    enabled: true\n    public: false\ntrust:\n  tool_allowlist:\n    - notes.writeNote\n`,
    );

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapInj005ChannelTrustLevel.run(model)).toHaveLength(1);
  });

  it('stays silent when the public channel has its own channel-specific allowlist override', () => {
    writeFileSync(
      path.join(dir, 'config.yaml'),
      `${CONFIG_HEADER}channels:\n  discord:\n    enabled: true\n    public: true\n    tool_allowlist:\n      - weather.fetchForecast\n  telegram_admin:\n    enabled: true\n    public: false\ntrust:\n  tool_allowlist:\n    - notes.writeNote\n`,
    );

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapInj005ChannelTrustLevel.run(model)).toEqual([]);
  });

  it('stays silent when every enabled channel is public (no private channel in the mix)', () => {
    writeFileSync(
      path.join(dir, 'config.yaml'),
      `${CONFIG_HEADER}channels:\n  discord:\n    enabled: true\n    public: true\n  slack:\n    enabled: true\n    public: true\ntrust:\n  tool_allowlist:\n    - notes.writeNote\n`,
    );

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapInj005ChannelTrustLevel.run(model)).toEqual([]);
  });

  it('stays silent when the global allowlist is empty (CHAP-INJ-003 already covers that gap)', () => {
    writeFileSync(
      path.join(dir, 'config.yaml'),
      `${CONFIG_HEADER}channels:\n  discord:\n    enabled: true\n    public: true\n  telegram_admin:\n    enabled: true\n    public: false\ntrust:\n  tool_allowlist: []\n`,
    );

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapInj005ChannelTrustLevel.run(model)).toEqual([]);
  });

  it('stays silent with only one enabled channel (nothing to compare trust levels against)', () => {
    writeFileSync(
      path.join(dir, 'config.yaml'),
      `${CONFIG_HEADER}channels:\n  discord:\n    enabled: true\n    public: true\ntrust:\n  tool_allowlist:\n    - notes.writeNote\n`,
    );

    const { model } = discoverAgent({ targetPath: dir });

    expect(chapInj005ChannelTrustLevel.run(model)).toEqual([]);
  });

  it('stays silent when there is no config at all', () => {
    const { model } = discoverAgent({ targetPath: dir });

    expect(chapInj005ChannelTrustLevel.run(model)).toEqual([]);
  });
});
