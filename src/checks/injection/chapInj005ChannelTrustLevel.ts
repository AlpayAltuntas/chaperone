import type { Check } from '../../engine/types.js';
import { getEnabledChannels, getTrustToolAllowlist } from '../shared/configAccess.js';

const ID = 'CHAP-INJ-005';
const TITLE = 'Inbound channels do not distinguish trust level';
const OWASP = 'LLM01: Prompt Injection';

/**
 * CHAP-INJ-003 only checks whether *a* global tool allowlist exists at
 * all — it doesn't ask whether different channels should carry
 * different trust levels (improvement_plan.md 2.9): a public Discord
 * server the agent listens on and a private, admin-only Telegram chat
 * currently look identical once any allowlist exists. This flags the
 * specific shape where at least one public/untrusted channel has no
 * channel-specific `tool_allowlist` narrowing it below the broad global
 * one, while at least one private/trusted channel is also enabled.
 */
export const chapInj005ChannelTrustLevel: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'injection',
  owasp: OWASP,
  detects:
    'A non-empty global tool allowlist applied uniformly to a mix of public and private inbound channels, with no channel-specific restriction narrowing what a public (untrusted) channel can invoke.',
  heuristic:
    'At least two channels are enabled, the global `trust.tool_allowlist` is non-empty, at least one enabled channel is public (`channels.<name>.public` — missing defaults to `true`/untrusted, same conservative-default posture as CHAP-INJ-001) with no channel-specific `channels.<name>.tool_allowlist` override, and at least one enabled channel is private (`public: false`). Same manifest-convention caveat as CHAP-AGY-003/004 — no real schema exists for these example agents.',
  remediation:
    'Declare a channel-specific tool_allowlist for each public/untrusted channel, narrower than what private/admin-only channels are permitted to invoke.',
  run(model) {
    if (model.config.path === null) {
      return [];
    }
    const channels = getEnabledChannels(model.config.data);
    if (channels.length < 2) {
      return [];
    }
    const globalAllowlist = getTrustToolAllowlist(model.config.data);
    if (globalAllowlist === null || globalAllowlist.length === 0) {
      return [];
    }

    const publicWithoutOverride = channels.filter(
      (channel) => channel.public && channel.toolAllowlist === null,
    );
    const hasPrivateChannel = channels.some((channel) => !channel.public);

    if (publicWithoutOverride.length === 0 || !hasPrivateChannel) {
      return [];
    }

    const publicNames = publicWithoutOverride.map((channel) => channel.name).join(', ');
    return [
      {
        checkId: ID,
        title: TITLE,
        severity: 'medium',
        category: 'injection',
        owasp: OWASP,
        message: `The global tool allowlist is applied uniformly to public channel(s) (${publicNames}) alongside at least one private channel, with no channel-specific restriction narrowing what the public channel(s) can invoke.`,
        location: { filePath: model.config.path, line: null, detail: 'trust.tool_allowlist' },
        remediation:
          'Declare a channel-specific tool_allowlist for each public/untrusted channel, narrower than what private/admin-only channels are permitted to invoke.',
      },
    ];
  },
};
