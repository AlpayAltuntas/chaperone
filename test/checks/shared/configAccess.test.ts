import { describe, expect, it } from 'vitest';
import {
  getTrustBoolean,
  getTrustToolAllowlist,
  isAnyChannelEnabled,
} from '../../../src/checks/shared/configAccess.js';
import type { JsonValue } from '../../../src/model/types.js';

describe('isAnyChannelEnabled', () => {
  it('returns true when at least one channel is enabled', () => {
    const data: JsonValue = {
      channels: { telegram: { enabled: true }, whatsapp: { enabled: false } },
    };
    expect(isAnyChannelEnabled(data)).toBe(true);
  });

  it('returns false when every channel is disabled', () => {
    const data: JsonValue = { channels: { telegram: { enabled: false } } };
    expect(isAnyChannelEnabled(data)).toBe(false);
  });

  it('returns false when there is no channels section or no config data', () => {
    expect(isAnyChannelEnabled({})).toBe(false);
    expect(isAnyChannelEnabled(null)).toBe(false);
  });
});

describe('getTrustBoolean', () => {
  it('reads a declared boolean field', () => {
    const data: JsonValue = { trust: { mark_untrusted_input: true } };
    expect(getTrustBoolean(data, 'mark_untrusted_input')).toBe(true);
  });

  it('returns null when the field or trust section is missing', () => {
    expect(getTrustBoolean({ trust: {} }, 'mark_untrusted_input')).toBeNull();
    expect(getTrustBoolean({}, 'mark_untrusted_input')).toBeNull();
    expect(getTrustBoolean(null, 'mark_untrusted_input')).toBeNull();
  });
});

describe('getTrustToolAllowlist', () => {
  it('reads a declared string array', () => {
    const data: JsonValue = { trust: { tool_allowlist: ['notes.writeNote'] } };
    expect(getTrustToolAllowlist(data)).toEqual(['notes.writeNote']);
  });

  it('returns null when absent or not a string array', () => {
    expect(getTrustToolAllowlist({ trust: {} })).toBeNull();
    expect(getTrustToolAllowlist({ trust: { tool_allowlist: [1, 2] } })).toBeNull();
  });
});
