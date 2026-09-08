# Changelog

# Changelog

## 0.3.7 — 2026-09-08

### Added
- Human-gated affirm-reply flow: GET /discord/replies/propose creates a pending proposal; GET /discord/replies/approve?proposal_id=ID&confirm=1 sends it once. Nothing auto-posts; proposals expire after one hour.
- db.py: reply_proposals table (status pending/approved/sent/expired/failed), UNIQUE (channel_id, source_message_id), atomic claim helper.
- Discord user/message context menu commands ("tinyPeople Connect", "tinyPeople Help") in addition to existing slash commands.
- Discord ingress telemetry (`/discord/interactions/ingress`) for interaction delivery debugging.
- Discord interaction timing metrics endpoint (`/discord/interactions/metrics`).
- Discord interactions endpoint aliases for routing compatibility (`/discord/interactions`, `/discord/interactions/`, `/api/discord/interactions`).

### Changed
- BOT_VERSION bumped to 0.3.7 (merges the 0.3.4 affirm-reply flow with the locally shipped 0.3.5/0.3.6 Discord interactions work)
- README and /help updated for the new endpoints
- /privacy updated: pending proposals hold source context and the proposed reply until approved, expired, or deleted.
- Hardened Discord slash payload parsing for type 2 interactions; enforced signature validation for PING interactions.

## 0.3.3 — 2026-07-19

### Changed
- `/messages` now preserves Discord embeds and supports `tp_embed_mode=raw|structured`.
- Debug responses for `/messages?tp_debug=1` include `embed_mode` and an embed usage hint.

## 0.3.2 — 2026-04-11

### Added
- Magic Link pairing flow for agent-driven OAuth: `/oauth/authorize?pairing_id=ID` now returns JSON
  with an `authorize_url` for the user and a `claim_url` for the agent.
- New `/oauth/claim?pairing_id=ID&tp_digest=DIGEST` endpoint: operator-authenticated one-time retrieval
  of the API key after user authorization — no copy-pasting required.
- `pairing_id` column added to `oauth_states` table (auto-migrated on first startup).

### Changed
- BOT_VERSION bumped to 0.3.2
- `/oauth/key` prune loop also clears `_PAIRING_INDEX` entries.

---

## 0.3.1 — 2026-04-11

### Changed
- BOT_VERSION bumped to 0.3.1
- OAuth show-once key retrieval TTL is now configurable via TP_OAUTH_SHOW_ONCE_TTL_SECONDS (default 300s)
- Added more actionable error guidance for auth/parameter issues (including invalid_digest hints)
- /health now includes sanitized endpoint_state setup signals (token/config booleans + aggregate tenant/key counts)

---

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
