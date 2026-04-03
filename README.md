# tinyPeople Discord Messages API

A minimal Flask service that exposes Discord channel messages through a shared-secret-protected HTTP endpoint.

Branding note: we style the name as `tinyPeople`, but hostnames and filesystem paths in commands/config remain lowercase.

## Endpoint Contract

- URL: `https://your-domain/messages`
- Method: `GET`
- Query params:
  - `channel_id` (required)
  - `limit` (optional, default from env)
- Auth:
  - Header `X-TinyPeople-Secret: <shared_secret>`
  - Or `Authorization: Bearer <shared_secret>`
  - Simple digest mode: `tp_digest=<digest>` (or header `X-TinyPeople-Digest`) with `ALLOW_STATIC_DIGEST_QUERY_PARAM=1`
  - Optional fallback (disabled by default): query param `tp_secret=<shared_secret>` when `ALLOW_SECRET_QUERY_PARAM=1`
  - Strong mode: timestamped signature (`tp_ts`, `tp_nonce`, `tp_sig`)
- Response:
  - JSON array of objects with:
    - `timestamp`
    - `author`
    - `content`

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

## Agent-Friendly Auth Options

Use one of these based on what your client can do.

1. Easiest (no crypto on client): set `TP_AGENT_DIGEST` in `.env` to a random long value, and have the client send `tp_digest=<that_exact_value>`.

1. Simple derived digest (one-time setup): set `TP_DIGEST_SALT` and `TP_SHARED_SECRET`, compute digest once as `sha256("<salt>:<shared_secret>")`, and have the client send that as `tp_digest`.

1. Strong signed requests (recommended for capable clients): send `tp_ts`, `tp_nonce`, and `tp_sig` where `tp_sig` is HMAC-SHA256 over the canonical payload; optionally enforce this mode with `REQUIRE_SIGNED_AUTH=1`.

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
