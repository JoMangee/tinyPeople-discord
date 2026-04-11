# Install and Deploy (cPanel)

**Version 0.3.0** — compatible with Python 3.12, Flask 2.3+, cPanel Passenger WSGI.

Branding note: use `tinyPeople` in copy/UI, but keep domain and host paths lowercase in operational commands.

## 1. Prepare a new Discord application

1. Open Discord Developer Portal.
2. Create a new application for tinyPeople messages API.
3. Add a bot and copy its token.
4. Grant bot to the target server with permission to:
   - View channel
   - Read message history
5. Keep this token isolated to server env only.

## 2. Upload project

Upload this folder to your host, for example:

- `/home/USERNAME/APPDOMAIN/`

## 3. Configure Python App in cPanel

Suggested:

- Python version: 3.12
- App root: `/home/USERNAME/APPDOMAIN`
- Startup file: `passenger_wsgi.py`
- URL: `https://your-domain`

## 4. Install dependencies

```bash
cd /home/USERNAME/APPDOMAIN
source /home/USERNAME/virtualenv/APPDOMAIN/3.12/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 5. Configure secrets

Create `.env` from `.env.example` and set:

- `DISCORD_TOKEN`: new Discord bot token for this service
- `TP_SHARED_SECRET`: strong random shared secret for callers
- `ALLOWED_CHANNEL_IDS`: optional comma-separated allowlist

Do not commit `.env`.

## 6. Restart Passenger app

```bash
touch /home/USERNAME/APPDOMAIN/tmp/restart.txt
```

## 7. Smoke test

```bash
curl -sS "https://your-domain/health"
curl -sS "https://your-domain/messages?channel_id=123456789012345678&limit=3" \
  -H "X-TinyPeople-Secret: your_shared_secret"
```

## 8. Git pull workflow

A typical pull workflow on host:

```bash
cd /home/USERNAME/APPDOMAIN
git pull
source /home/USERNAME/virtualenv/APPDOMAIN/3.12/bin/activate
python -m pip install -r requirements.txt
touch tmp/restart.txt
```

For cPanel Git Version Control deployment, `.cpanel.yml` handles these steps automatically.

## 9. Local ops deployment workflow

Run deployment and verification from your local ops workspace (`C:/Data/web/ops`) using the tinyPeople-prefixed scripts. Keep host-specific values in local-only env files there (not in this repository).
