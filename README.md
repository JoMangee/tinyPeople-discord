# tinyPeople Discord Messages API

**Version 0.3.7** — see [CHANGELOG.md](CHANGELOG.md) for history.

A Flask API that reads Discord channel messages via a bot token kept server-side.

Branding note: display name is tinyPeople; operational hostnames and filesystem paths are lowercase.

## Quick Start for Humans

Just click the magic link your tinyPeople agent gives you, approve the connection in Discord
(you choose which servers/channels it can see), and you'll get a personal tp_key in seconds.
No bot tokens or developer portal needed. Use that key to fetch messages.
Try it now: ask your tinyNature for a pairing link and you're good to go.

## Core Endpoints

- GET /messages
- GET /image-chunk
- GET /health
- GET /discord/mentions/respond
- GET /discord/replies/propose
- GET /discord/replies/approve
- GET /oauth/authorize
- GET /oauth/link
- GET /oauth/status
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

```text
https://discord.com/channels/GUILD_ID/CHANNEL_ID
https://discord.com/channels/GUILD_ID/CHANNEL_ID/MESSAGE_ID
https://discord.com/channels/@me/CHANNEL_ID
https://discord.com/channels/@me/CHANNEL_ID/MESSAGE_ID
```

`@me` URLs are only valid for one-to-one DMs with the bot. They require a tenant API key that is bound to the Discord user who owns that DM, and they will not allow admins or other tenants to read someone else's bot DMs.

Optional query params:

- limit (default from env)
- message_id (exact message fetch)
- tp_image_mode=raw (include base64 image chunks)
- tp_embed_mode=raw|structured (raw Discord embeds by default; structured is a compact projection for limited agents)
- tp_debug=1 (when ALLOW_DEBUG_QUERY_PARAM=1)

The response keeps Discord embeds in an `embeds` field. Use `tp_embed_mode=structured` for a compact embed projection; leave it unset to receive raw Discord embed JSON. When a message has no plain text content, the API falls back to a compact text summary built from embed title/description so embed-only announcements are still readable.

Small example:

```text
Raw embeds:
GET /messages?channel_id=CHANNEL_ID&message_id=MESSAGE_ID&tp_key=YOUR_API_KEY

Structured embeds:
GET /messages?channel_id=CHANNEL_ID&message_id=MESSAGE_ID&tp_embed_mode=structured&tp_key=YOUR_API_KEY

One-to-one bot DM by Discord URL:
GET /messages?discord_url=https://discord.com/channels/@me/CHANNEL_ID/MESSAGE_ID&tp_key=YOUR_API_KEY
```

Repo-local ingest guide: [docs/tinyPeople-discord-channel-ingest-public.md](docs/tinyPeople-discord-channel-ingest-public.md)

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
  `GET /oauth/authorize`
  Agent/chat shortcut (auto-generates pairing_id and returns JSON links): `GET /oauth/link`
  Optional context (for message handoff tooling): `GET /oauth/link?discord_url=https://discord.com/channels/@me/CHANNEL_ID/MESSAGE_ID`

2. Discord redirects back:
  `GET /oauth/callback`

3. Agent polls pairing status:
  `GET /oauth/status?pairing_id=PAIRING_ID`

4. Agent retrieves key once when status is ready_to_claim:
  `GET /oauth/claim?pairing_id=PAIRING_ID`

Manual fallback:
  `GET /oauth/key?token=SHOW_ONCE_TOKEN`

The raw API key is only retrievable once and is not stored in plaintext.

Discord UI hook:

- Register slash commands with `GET /discord/commands/sync`.
- Use `/connect` inside Discord to generate an ephemeral authorize/status/claim flow message.

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

## Mention Status Replies

Enable mention status replies with `MENTION_REPLY_ENABLED=1`.

Endpoint:

- GET /discord/mentions/respond?channel_id=CHANNEL_ID (with X-TinyPeople-Key header)
- GET /discord/mentions/respond?channel_id=CHANNEL_ID (with X-TinyPeople-Digest header)

Example auth headers:

- `X-TinyPeople-Key: YOUR_API_KEY`
- `X-TinyPeople-Digest: YOUR_DIGEST`

Behavior:

- Scans recent messages for mentions of the bot.
- Supports `mode=respond` (default) and `mode=query`.
- `mode=respond` replies in-thread to mention messages.
- `mode=query` is read-only and returns mention candidates + activity status.
- Uses cooldown tracking and Discord-history checks to avoid duplicate replies.

How to use it:

1. Query first to find the mention you want to answer.
2. Copy that candidate's `message_id` into the respond call.
3. If the mention is older than the default scan window, raise `scan_limit` and keep `lookback_limit` at or above it.

Optional query params:

- scan_limit (1..100, default from env)
- lookback_limit (scan_limit..200, default from env)
- max_replies (1..3, default from env)
- mode (`query` or `respond`, default `respond`)
- message_ids (optional comma-separated Discord message IDs to target in `respond` mode)
- reply_message (optional caller-authored text in `respond` mode)

Query mode returns:

- `candidates[]` with `message_id`, `user_id`, `mention_content`, `timestamp`, light `author` metadata, and `activity_status`
- `most_recent_mention` supplementary context with `message_id` and `recent_message_preview`

Important:

- `message_ids` is the Discord message ID of the mention, not the channel ID.
- `mode=respond` will only target messages that are still inside the scan window.

Mode examples:

```text
GET /discord/mentions/respond?channel_id=CHANNEL_ID&mode=query&tp_key=YOUR_API_KEY
```

```text
GET /discord/mentions/respond?channel_id=CHANNEL_ID&mode=respond&message_ids=MESSAGE_ID&reply_message=I%20am%20here%20and%20I%20can%20read%20this%20channel.&tp_key=YOUR_API_KEY
```

Bash helper:

- [ops/scripts/poll_mentions.sh](ops/scripts/poll_mentions.sh)

Behavior:

- Loads [ops/scripts/poll_mentions.sh](ops/scripts/poll_mentions.sh) settings from the repo `.env` by default.
- Accepts one or more channel IDs as positional arguments.
- Can also read `TP_CHANNEL_IDS` from `.env` as a comma-separated list.

Example usage:

```bash
TP_KEY=YOUR_API_KEY ./ops/scripts/poll_mentions.sh 1495644139805474907
```

Multiple channels in one run:

```bash
./ops/scripts/poll_mentions.sh 1495644139805474907 1495644139805474908
```

`.env`-driven usage:

```bash
TP_CHANNEL_IDS=1495644139805474907,1495644139805474908
TP_KEY=YOUR_API_KEY
TP_BASE_URL=https://tinypeople.mesh.net.nz
TP_OUTPUT_MODE=summary
./ops/scripts/poll_mentions.sh
```

Digest-auth usage (when TP_KEY is not configured server-side):

```bash
TP_AGENT_DIGEST=YOUR_DIGEST
TP_BASE_URL=https://tinypeople.mesh.net.nz
TP_OUTPUT_MODE=summary
./ops/scripts/poll_mentions.sh 1495644139805474907
```

Output modes:

- `full`: print each full JSON response
- `summary`: print one compact line per channel
- `failures`: only print response bodies for non-2xx requests

Example crontab:

```cron
* * * * * TP_OUTPUT_MODE=summary /usr/bin/env bash /home/USERNAME/APPDOMAIN/ops/scripts/poll_mentions.sh 1495644139805474907 1495644139805474908 >> /home/USERNAME/tinyPeople-mentions.log 2>&1
```

## Minimal Examples

Get a tenant key first via the Magic Link flow, then set:

API_KEY = /oauth/claim response field api_key

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

See channels your key can access (public + tenant grants):

```text
https://YOUR_DOMAIN/channels/list?tp_key=YOUR_API_KEY
```

## Discord Developer Portal URLs

- Terms of Service URL: https://YOUR_DOMAIN/terms
- Privacy Policy URL: https://YOUR_DOMAIN/privacy
- Interactions Endpoint URL: https://YOUR_DOMAIN/discord/interactions
- Linked Roles Verification URL: leave blank unless implementing linked roles verification

If you enable Discord slash commands for this app, keep the Interactions Endpoint URL pointed at `/discord/interactions`, set `DISCORD_APP_PUBLIC_KEY` from Developer Portal > General Information, and register commands with `/discord/commands/sync` after deploy.

Operator checklist for interactions:

1. Set `DISCORD_APP_PUBLIC_KEY` from Discord Developer Portal > General Information.
2. Deploy with `DISCORD_INTERACTIONS_ENABLED=1`.
3. Set Interactions Endpoint URL to `https://YOUR_DOMAIN/discord/interactions` and save.
4. Verify runtime wiring with `GET /discord/interactions/health`.
5. Register slash commands with `GET /discord/commands/sync` using operator digest auth.
6. If Discord still fails verification or command delivery, inspect the last probe with `GET /discord/interactions/last` using operator digest auth.

Channel access troubleshooting:

- `/channels/grant` only grants tenant-side allowlisting inside this API. It does not change Discord permissions.
- `discord_channel_not_found` usually means the bot cannot see that guild channel or thread, or the channel ID is not a guild channel for this bot.
- Private threads require the bot to be an explicit thread member in addition to normal channel visibility.
- This API is guild-scoped. It does not support reading arbitrary user DM history, and there is no Discord permission toggle or repo command that grants that capability.

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
- DISCORD_APP_PUBLIC_KEY
- DISCORD_INTERACTIONS_ENABLED
- TP_SERVICE_NAME
- TP_BASE_URL
- TP_CONTACT_EMAIL

Keep real values in local environment files only. Do not commit production hostnames, OAuth secrets, public keys, API keys, or deploy-specific overrides.

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
