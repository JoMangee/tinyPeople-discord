# Changelog

## 0.3.0 — 2026-04-11

### Added
- Key lifecycle endpoints: GET /keys, /keys/issue, /keys/revoke
- /health now returns public server-load telemetry (request rate, unique hosts)
- /health returns per-key rate-limit usage (requests_in_window, remaining_requests, reset_in_seconds) when tp_key supplied
- db.py: get_rate_limit_usage, list_api_keys_for_tenant, count_active_api_keys, revoke_api_key
- Terms of Service page at /terms and Privacy Policy page at /privacy (Discord Developer Portal requirements)
- TP_SERVICE_NAME, TP_BASE_URL, TP_CONTACT_EMAIL env vars for public-facing identity

### Changed
- BOT_VERSION bumped to 0.3.0
- .cpanel.yml genericized with /home/USERNAME/APPDOMAIN placeholders for public fork use
- README rewritten to reflect current API surface (OAuth, key lifecycle, health telemetry, Discord portal URLs)
- .env.example deduplication and addition of new vars

---

## 0.2.0 — 2026-04-04

### Added
- Discord OAuth install flow: GET /oauth/authorize, /oauth/callback, /oauth/key
- discord_url parameter on /messages accepts raw Discord copy-link URLs
  (https://discord.com/channels/GUILD/CHANNEL/MESSAGE)
- Auth errors return install_url + install_hint to guide agents through authorization
- Show-once API key pattern: raw key held in memory 60s after OAuth, then discarded
- db.py: create_or_get_tenant, mint_api_key, store_oauth_state, consume_oauth_state,
  get_tenant_by_guild, add_channel_grant
- DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_OAUTH_REDIRECT_URI, TP_OAUTH_ENABLED env vars

---

## 0.1.0 — 2026-04-03

### Added
- Initial Flask API: GET /messages, GET /health, GET /
- Shared-secret auth ladder: signed HMAC, static digest, bearer/header secret
- GET query-param parity for all auth modes (agent-friendly)
- db.py: SQLite-backed multi-tenant foundation (WAL mode, thread-local connections)
- Tenants, api_keys, channel_grants, rate_limit_buckets, audit_log, oauth_states schema
- Per-key rolling rate limit enforcement
- Audit log on every authenticated request
- TP_ENABLE_API_KEYS, TP_RATE_LIMIT_PER_MINUTE, TP_RATE_LIMIT_WINDOW_SECONDS, TP_DB_PATH env vars
- cPanel Passenger WSGI deploy via .cpanel.yml
- Rolling /messages request telemetry (request rate, unique hosts)
