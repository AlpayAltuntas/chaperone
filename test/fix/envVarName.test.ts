import { describe, expect, it } from 'vitest';
import { suggestEnvVarName } from '../../src/fix/envVarName.js';

describe('suggestEnvVarName', () => {
  it('uppercases and joins a simple dotted path', () => {
    expect(suggestEnvVarName('llm.api_key')).toBe('LLM_API_KEY');
  });

  it('uses the full path, not just the leaf, to avoid collisions', () => {
    expect(suggestEnvVarName('channels.telegram.bot_token')).toBe('CHANNELS_TELEGRAM_BOT_TOKEN');
    expect(suggestEnvVarName('channels.discord.bot_token')).toBe('CHANNELS_DISCORD_BOT_TOKEN');
  });

  it('drops array indices rather than embedding brackets', () => {
    expect(suggestEnvVarName('servers[0].token')).toBe('SERVERS_TOKEN');
  });

  it('handles a single-segment path', () => {
    expect(suggestEnvVarName('api_key')).toBe('API_KEY');
  });
});
