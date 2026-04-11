# tinyPeople Discord Messages API

**Version 0.3.2** — see [CHANGELOG.md](CHANGELOG.md) for history.

A Flask API that reads Discord channel messages via a bot token kept server-side.

Branding note: display name is tinyPeople; operational hostnames and filesystem paths are lowercase.

## Core Endpoints

- GET /messages
- GET /image-chunk
- GET /health
- GET /oauth/authorize
- GET /oauth/callback
- GET /oauth/key
- GET /keys
- GET /keys/issue
- GET /keys/revoke
- GET /terms
- GET /privacy

## Authentication Modes

Use one mode per request.

1. API key mode (multi-tenant):
  Send tp_key in query string or X-TinyPeople-Key header.

2. Shared secret mode (legacy/operator):
  Send X-TinyPeople-Secret or Authorization Bearer.

3. Static digest mode (agent-friendly):
  Send tp_digest (or X-TinyPeople-Digest) when ALLOW_STATIC_DIGEST_QUERY_PARAM=1.

4. Signed request mode (strongest):
  Send tp_ts, tp_nonce, tp_sig where tp_sig is HMAC-SHA256 over canonical payload.

If REQUIRE_SIGNED_AUTH=1, only signed requests are accepted for legacy auth paths.

## Messages API

GET /messages accepts either:

- channel_id (required if discord_url absent)
- discord_url in Discord copy-link format:
  https://discord.com/channels/GUILD_ID/CHANNEL_ID
  https://discord.com/channels/GUILD_ID/CHANNEL_ID/MESSAGE_ID

Optional query params:

- limit (default from env)
- message_id (exact message fetch)
- tp_image_mode=raw (include base64 image chunks)
- tp_debug=1 (when ALLOW_DEBUG_QUERY_PARAM=1)

API key requests are tenant-scoped. A key can only access channels granted to its tenant.

## Key Lifecycle API (Tenant Scoped)

All key lifecycle routes require a valid tenant API key in tp_key (or X-TinyPeople-Key).

1. List keys:
  GET /keys
  Optional: include_revoked=1

2. Issue a new key:
  GET /keys/issue
  Returns a new raw api_key once.

3. Revoke a key:
  GET /keys/revoke?key_id=YOUR_KEY_ID
  Safety rule: cannot revoke the caller key if it is the tenant's last active key.

## OAuth Install Flow

Enable with TP_OAUTH_ENABLED=1 and Discord OAuth settings in .env.

1. User starts install:
  GET /oauth/authorize

2. Discord redirects back:
  GET /oauth/callback

3. Retrieve key once:
  GET /oauth/key?token=SHOW_ONCE_TOKEN

The raw API key is only retrievable once and is not stored in plaintext.

## Health and Telemetry

GET /health always returns safe server-load telemetry:

- messages_telemetry.requests_in_window
- messages_telemetry.request_rate_per_minute
- messages_telemetry.unique_hosts_in_window

If tp_key is supplied and valid, /health also returns key-specific limit status:

- rate_limit.max_requests
- rate_limit.window_seconds
- rate_limit.requests_in_window
- rate_limit.remaining_requests
- rate_limit.reset_in_seconds

If legacy auth is supplied and valid, /health includes operator signals such as has_discord_token and has_shared_secret.

## Raw Image Mode

For text-only clients, set tp_image_mode=raw on /messages.

Each raw_images entry contains:

- encoding (base64)
- chunk_chars
- chunk_count
- chunks (ordered base64 segments)

Use /image-chunk for on-demand chunk fetch by URL and index.

## Minimal Examples

Digest mode:

```text
https://YOUR_DOMAIN/messages?channel_id=CHANNEL_ID&limit=5&tp_digest=YOUR_DIGEST
```

Discord URL mode with API key:

```text
https://YOUR_DOMAIN/messages?discord_url=https://discord.com/channels/GUILD_ID/CHANNEL_ID/MESSAGE_ID&tp_key=YOUR_API_KEY
```

Health with key budget info:

```text
https://YOUR_DOMAIN/health?tp_key=YOUR_API_KEY
```

## Discord Developer Portal URLs

- Terms of Service URL: https://YOUR_DOMAIN/terms
- Privacy Policy URL: https://YOUR_DOMAIN/privacy
- Interactions Endpoint URL: leave blank unless implementing interaction webhooks
- Linked Roles Verification URL: leave blank unless implementing linked roles verification

## Environment

Start from .env.example and set production values for:

- DISCORD_TOKEN
- TP_SHARED_SECRET
- TP_ENABLE_API_KEYS
- TP_DB_PATH
- TP_OAUTH_ENABLED
- DISCORD_CLIENT_ID
- DISCORD_CLIENT_SECRET
- DISCORD_OAUTH_REDIRECT_URI
- TP_SERVICE_NAME
- TP_BASE_URL
- TP_CONTACT_EMAIL

## Local Run

```bash
pip install -r requirements.txt
cp .env.example .env
python app.py
```

## Deployment Notes

- Passenger entrypoint: passenger_wsgi.py
- `.cpanel.yml` is an example template with placeholders (`USERNAME`, `APPDOMAIN`).
- Keep your real host-specific deployment file in a local gitignored override (for example `.cpanel.yml.USERNAME`).
- Keep host-specific secrets and SSH details in local gitignored files only.
- Use ops/scripts/Use-TinyPeopleRepoEnv.ps1 for repository-local SSH environment setup.
