# Kill switch (DUMMY fixture doc for Chaperone's own test suite)

To stop this agent and revoke its access:

1. Stop the gateway service (e.g. `launchctl unload`/`systemctl stop` the
   agent's service unit).
2. Revoke and rotate every credential referenced in `config.yaml`
   (`ANTHROPIC_API_KEY`, `TELEGRAM_BOT_TOKEN`, `GATEWAY_AUTH_TOKEN`) at
   their respective providers.
3. Remove the gateway's auth token from wherever it's stored so a stale
   process can't keep using it.
