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
