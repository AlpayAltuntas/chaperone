/**
 * Suggests an environment-variable name for a config keyPath like
 * `llm.api_key` -> `LLM_API_KEY`, or `channels.telegram.bot_token` ->
 * `CHANNELS_TELEGRAM_BOT_TOKEN`. Uses the *full* dotted path, not just
 * the leaf key — `telegram.bot_token` and `discord.bot_token` must not
 * collide on the same suggested variable name. Array indices (`[0]`)
 * are dropped rather than embedded in the name (an env var name can't
 * contain brackets); a repeated index within one file would collide,
 * a known, narrow limitation for the array case specifically.
 */
export function suggestEnvVarName(keyPath: string): string {
  return keyPath
    .replace(/\[\d+\]/g, '')
    .split('.')
    .filter((segment) => segment.length > 0)
    .join('_')
    .toUpperCase();
}
