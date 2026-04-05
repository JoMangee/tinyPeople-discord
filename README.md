# tinyPeople Discord Messages API

A minimal Flask service that exposes Discord channel messages through a shared-secret-protected HTTP endpoint.

Branding note: we style the name as `tinyPeople`, but hostnames and filesystem paths in commands/config remain lowercase.

## Endpoint Contract

- URL: `https://your-domain/messages`
- Method: `GET`
- Query params:
  - `channel_id` (required)
  - `limit` (optional, default from env)
  - `message_id` (optional, fetch exact message when provided)
  - `tp_image_mode=raw` (optional, include base64 image chunks for text-only agents)
- Auth:
  - Header `X-TinyPeople-Secret: <shared_secret>`
  - Or `Authorization: Bearer <shared_secret>`
  - Simple digest mode: `tp_digest=<digest>` (or header `X-TinyPeople-Digest`) with `ALLOW_STATIC_DIGEST_QUERY_PARAM=1`
  - Optional fallback (disabled by default): query param `tp_secret=<shared_secret>` when `ALLOW_SECRET_QUERY_PARAM=1`
  - Strong mode: timestamped signature (`tp_ts`, `tp_nonce`, `tp_sig`)
- Response:
  - JSON array of objects with:
    - `timestamp`
    - `message_id`
    - `author`
    - `content`
    - `attachment_urls`
    - `image_urls`
    - `raw_images` (only when `tp_image_mode=raw`)

## Raw Image Mode

For text-only agents that can process chunked payloads, request raw image data:

```text
/messages?...&tp_image_mode=raw
```

Each `raw_images` item includes:

1. `encoding` (`base64`)
1. `chunk_chars` and `chunk_count`
1. `chunks` array (base64 segments in order)

Limits are controlled by `RAW_IMAGE_MODE_MAX_BYTES`, `RAW_IMAGE_CHUNK_CHARS`, and `RAW_IMAGE_MAX_ATTACHMENTS`.

## Why this keeps token at arm's length

- The external agent only knows the shared secret.
- Discord bot token stays server-side in `.env`.
- The service does not return or log token values.
- Optional `ALLOWED_CHANNEL_IDS` can constrain what channel IDs are queryable.
- Keep `ALLOW_SECRET_QUERY_PARAM=0` unless required, because query strings may be logged by proxies and web servers.

## Health Telemetry

`/health` includes a `messages_telemetry` object with in-memory rolling stats:

1. `requests_in_window`: number of `/messages` requests in the recent window.
1. `request_rate_per_minute`: normalized rate derived from that window.
1. `unique_hosts_in_window`: number of unique client IPs seen recently.

Tune window sizes with `METRICS_WINDOW_SECONDS` and `UNIQUE_HOST_WINDOW_SECONDS`.

## Debug Query Mode

For targeted troubleshooting, enable `ALLOW_DEBUG_QUERY_PARAM=1` and call:

```text
/messages?...&tp_debug=1
```

When enabled, responses include a `debug` object with non-secret diagnostics such as Discord upstream status/code and thread access hints.

## Agent-Friendly Auth Options

Use one of these based on what your client can do.

1. Easiest (no crypto on client): set `TP_AGENT_DIGEST` in `.env` to a random long value, and have the client send `tp_digest=<that_exact_value>`.

1. Simple derived digest (one-time setup): set `TP_DIGEST_SALT` and `TP_SHARED_SECRET`, compute digest once as `sha256("<salt>:<shared_secret>")`, and have the client send that as `tp_digest`.

1. Strong signed requests (recommended for capable clients): send `tp_ts`, `tp_nonce`, and `tp_sig` where `tp_sig` is HMAC-SHA256 over the canonical payload; optionally enforce this mode with `REQUIRE_SIGNED_AUTH=1`.

## Example URLs (Digest Mode)

Replace placeholders with your values:

1. `YOUR_DOMAIN` (for example `api.example.com`)
1. `CHANNEL_ID`
1. `MESSAGE_ID`
1. `YOUR_DIGEST` (configured `TP_AGENT_DIGEST` or derived digest)

1. Latest messages from a thread/channel:

```text
https://YOUR_DOMAIN/messages?channel_id=CHANNEL_ID&limit=5&tp_digest=YOUR_DIGEST
```

1. Exact message by message ID:

```text
https://YOUR_DOMAIN/messages?channel_id=CHANNEL_ID&message_id=MESSAGE_ID&tp_digest=YOUR_DIGEST
```

1. Include debug diagnostics:

```text
https://YOUR_DOMAIN/messages?channel_id=CHANNEL_ID&limit=5&tp_digest=YOUR_DIGEST&tp_debug=1
```

1. Include raw image chunks for text-only agents:

```text
https://YOUR_DOMAIN/messages?channel_id=CHANNEL_ID&message_id=MESSAGE_ID&tp_digest=YOUR_DIGEST&tp_image_mode=raw
```

Equivalent curl examples:

```bash
curl -sS "https://YOUR_DOMAIN/messages?channel_id=CHANNEL_ID&limit=5&tp_digest=YOUR_DIGEST"
curl -sS "https://YOUR_DOMAIN/messages?channel_id=CHANNEL_ID&message_id=MESSAGE_ID&tp_digest=YOUR_DIGEST"
curl -sS "https://YOUR_DOMAIN/messages?channel_id=CHANNEL_ID&message_id=MESSAGE_ID&tp_digest=YOUR_DIGEST&tp_image_mode=raw"
```

## Quick Start

1. Create and activate virtual environment.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Copy env template and set real secrets:

   ```bash
   cp .env.example .env
   ```

4. Run locally:

   ```bash
   python app.py
   ```

5. Test endpoint:

   ```bash
   curl -sS "http://127.0.0.1:8080/messages?channel_id=123456789012345678&limit=5" \
     -H "X-TinyPeople-Secret: your_shared_secret"
   ```

   Headerless client compatibility test:

   ```bash
   ALLOW_SECRET_QUERY_PARAM=1 python app.py
   curl -sS "http://127.0.0.1:8080/messages?channel_id=123456789012345678&limit=5&tp_secret=your_shared_secret"
   ```

## Deploy Pattern

This project mirrors the existing USERNAME pattern:

- Git push/pull deploy style
- `.cpanel.yml` deployment tasks
- runtime stamp in `.deploy-stamp.env`
- Passenger app via `passenger_wsgi.py`
- host logs in `deploy-logs/cpanel-deploy-latest.log`

Adjust hardcoded host paths in `.cpanel.yml` to match your cPanel environment.

## Local Operations Workflow

Operational deployment and host verification scripts are intentionally kept in your local ops workspace (`C:/Data/web/ops`) rather than this project repository.

Use the tinyPeople scripts there:

- `scripts/deploy-tinyPeople-cpanel.ps1`
- `scripts/deploy-tinyPeople-cpanel.sh`
- `scripts/verify-tinyPeople-deploy.ps1`
- `scripts/verify-tinyPeople-deploy.sh`

This keeps server-specific paths, SSH details, and operational runbooks out of the shared project codebase.
