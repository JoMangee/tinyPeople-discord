# tinyPeople Discord Channel Ingest (Public)

## Overview

How to use tinyPeople to authenticate, grant channel access, and ingest messages from Discord channels. This is the core workflow for asking tinyNature to check a Discord link and summarise what is happening inside.

## Base URL

https://tinypeople.mesh.net.nz

## Authentication

All authenticated requests use `tp_key` unless you are using legacy shared-secret or digest modes.

Recommended path:

1. Start a Magic Link pairing with `/oauth/authorize?pairing_id=...`
2. Send the returned `authorize_url` to the user
3. After the user authorizes, claim the key with `/oauth/claim?pairing_id=...`
4. Use the returned `api_key` as `tp_key`

## Quick Start

### 1. Pairing

GET /oauth/authorize?pairing_id=tp-pair-example-001

### 2. Claim

GET /oauth/claim?pairing_id=tp-pair-example-001

### 3. Health check

GET /health?tp_key=YOUR_KEY

### 4. List and grant channel access

GET /channels/list?tp_key=YOUR_KEY

GET /channels/grant?channel_id=CHANNEL_ID&tp_key=YOUR_KEY

### 5. Pull messages

GET /messages?channel_id=CHANNEL_ID&limit=50&tp_key=YOUR_KEY

Or use a Discord URL:

GET /messages?discord_url=ENCODED_DISCORD_URL&limit=50&tp_key=YOUR_KEY

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
