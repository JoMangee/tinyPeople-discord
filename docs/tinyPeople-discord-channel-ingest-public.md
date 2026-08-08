# tinyPeople Discord Channel Ingest (Public)

## Overview

How to use the tinyPeople discord bot to authenticate, grant channel access, and ingest messages from Discord channels. This is the core (non official) workflow for asking tinyNature to check a Discord link and summarise what is happening inside.

## Base URL

```text
https://tinypeople.mesh.net.nz
```

## Authentication

All authenticated requests use `tp_key` unless you are using legacy shared-secret or digest modes.

Recommended path:

1. Start a Magic Link pairing with `/oauth/link` (auto-generated pairing_id) or `/oauth/authorize?pairing_id=...`
2. Send the returned `authorize_url` to the user
3. Poll `/oauth/status?pairing_id=...` until status is `ready_to_claim`
4. Claim the key with `/oauth/claim?pairing_id=...`
5. Use the returned `api_key` as `tp_key`

Discord UI shortcut:

- After running `/discord/commands/sync`, users can run `/connect` in Discord to receive an ephemeral authorize link plus status/claim URLs.

## Quick Start

### 1. Pairing

GET /oauth/link

Or explicit pairing ID:

GET /oauth/authorize?pairing_id=tp-pair-example-001

### 2. Claim

GET /oauth/claim?pairing_id=tp-pair-example-001

Optional polling status:

GET /oauth/status?pairing_id=tp-pair-example-001

### 3. Health check

GET /health?tp_key=YOUR_KEY

### 4. List and grant channel access

GET /channels/list?tp_key=YOUR_KEY

GET /channels/grant?channel_id=CHANNEL_ID&tp_key=YOUR_KEY

### 5. Pull messages

GET /messages?channel_id=CHANNEL_ID&limit=50&tp_key=YOUR_KEY

Or use a Discord URL:

GET /messages?discord_url=ENCODED_DISCORD_URL&limit=50&tp_key=YOUR_KEY

One-to-one bot DMs are also supported with Discord `@me` links, but only when the API key is bound to the Discord user who owns that DM. This prevents other tenants or operators from using a different key to read someone else's bot DM history.

### 6. Fetch a specific message

GET /messages?channel_id=CHANNEL_ID&message_id=MESSAGE_ID&tp_key=YOUR_KEY

## Message Shapes

`/messages` returns message JSON with:

- `message_id`
- `author`
- `content`
- `timestamp`
- `attachment_urls`
- `image_urls`
- `embeds`

Embed handling supports two modes:

- `tp_embed_mode=raw` keeps the raw Discord embed payload
- `tp_embed_mode=structured` returns a compact projection for limited agents

Example:

```text
GET /messages?channel_id=CHANNEL_ID&message_id=MESSAGE_ID&tp_key=YOUR_KEY
GET /messages?channel_id=CHANNEL_ID&message_id=MESSAGE_ID&tp_embed_mode=structured&tp_key=YOUR_KEY
```

If a message has no plain text content, the API falls back to a short summary built from embed title and description so embed-only announcements are still readable.

## Mention Status Replies

Endpoint:

GET /discord/mentions/respond?channel_id=CHANNEL_ID

Authentication:

- `X-TinyPeople-Key: YOUR_API_KEY`
- `X-TinyPeople-Digest: YOUR_DIGEST`

Query parameters:

- `scan_limit` - 1..100
- `lookback_limit` - scan_limit..200
- `max_replies` - 1..3
- `mode=query|respond`
- `message_ids` - optional comma-separated Discord message IDs
- `reply_message` - optional caller-authored response text

Example query:

```text
GET /discord/mentions/respond?channel_id=CHANNEL_ID&mode=query&tp_key=YOUR_KEY
```

Example reply:

```text
GET /discord/mentions/respond?channel_id=CHANNEL_ID&mode=respond&message_ids=MESSAGE_ID&reply_message=Hello%20from%20tinyNature&tp_key=YOUR_KEY
```

## Polling Helper

Use [ops/scripts/poll_mentions.sh](../ops/scripts/poll_mentions.sh) for self-hosted polling.

Example:

```bash
TP_KEY=YOUR_API_KEY ./ops/scripts/poll_mentions.sh CHANNEL_ID
```

## Notes

- `/help` exposes a plain-text quickstart for operators and agents
- `/channels/grant` and `/channels/revoke` are tenant-scoped
- `tp_embed_mode=structured` is the best fit for limited agents
- The repo version is `0.3.3`
