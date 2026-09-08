#!/usr/bin/env python3
"""tinyPeople Discord Messages API.

Provides a shared-secret-protected endpoint that fetches latest messages
from a Discord channel using a bot token that stays server-side.
"""

from __future__ import annotations

import base64
from collections import deque
from datetime import datetime, timezone
import hmac
import hashlib
import html
from urllib.parse import quote
import json
import os
import re
import secrets
from threading import Lock
import time
from dataclasses import dataclass
from typing import Any

import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request
try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
except ImportError:
    BadSignatureError = Exception
    VerifyKey = None

try:
    from db import get_db, init_db, AuthContext
except ImportError:
    # db module optional; can run without multi-tenant features
    get_db = None
    init_db = None
    AuthContext = None

BOT_VERSION = "0.3.4"
APP_DIR = os.path.dirname(__file__)
load_dotenv(os.path.join(APP_DIR, ".env"))
load_dotenv(os.path.join(APP_DIR, ".deploy-stamp.env"))
# Initialize database for multi-tenant features (optional)
if init_db:
    TP_DB_PATH = os.getenv("TP_DB_PATH", "var/tinypeople.db")
    if not os.path.isabs(TP_DB_PATH):
        TP_DB_PATH = os.path.join(APP_DIR, TP_DB_PATH)
    os.makedirs(os.path.dirname(TP_DB_PATH), exist_ok=True)
    init_db(TP_DB_PATH)
APP_REVISION = os.getenv("POD_APP_REVISION", "dev")
APP_BUILD = os.getenv("POD_APP_BUILD", "local")
APP_RUNTIME_SIGNATURE = f"v{BOT_VERSION} | rev {APP_REVISION} | build {APP_BUILD}"

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
TP_SHARED_SECRET = os.getenv("TP_SHARED_SECRET", "").strip()
TP_AGENT_DIGEST = os.getenv("TP_AGENT_DIGEST", "").strip().lower()
ALLOW_DEBUG_QUERY_PARAM = (
    os.getenv("ALLOW_DEBUG_QUERY_PARAM", "0").strip().lower()
    in {"1", "true", "yes", "on"}
)
ALLOW_SECRET_QUERY_PARAM = (
    os.getenv("ALLOW_SECRET_QUERY_PARAM", "0").strip().lower()
    in {"1", "true", "yes", "on"}
)
ALLOW_STATIC_DIGEST_QUERY_PARAM = (
    os.getenv("ALLOW_STATIC_DIGEST_QUERY_PARAM", "1").strip().lower()
    in {"1", "true", "yes", "on"}
)
TP_DIGEST_SALT = os.getenv("TP_DIGEST_SALT", "").strip()
ALLOW_SIGNED_QUERY_PARAM = (
    os.getenv("ALLOW_SIGNED_QUERY_PARAM", "1").strip().lower()
    in {"1", "true", "yes", "on"}
)
REQUIRE_SIGNED_AUTH = (
    os.getenv("REQUIRE_SIGNED_AUTH", "0").strip().lower()
    in {"1", "true", "yes", "on"}
)
SIGNED_TIMESTAMP_TOLERANCE_SECONDS = int(
    os.getenv("SIGNED_TIMESTAMP_TOLERANCE_SECONDS", "300")
)
METRICS_WINDOW_SECONDS = int(os.getenv("METRICS_WINDOW_SECONDS", "60"))
UNIQUE_HOST_WINDOW_SECONDS = int(os.getenv("UNIQUE_HOST_WINDOW_SECONDS", "300"))
RAW_IMAGE_MODE_MAX_BYTES = int(os.getenv("RAW_IMAGE_MODE_MAX_BYTES", "786432"))
RAW_IMAGE_CHUNK_CHARS = int(os.getenv("RAW_IMAGE_CHUNK_CHARS", "12000"))
RAW_IMAGE_FETCH_TIMEOUT_SECONDS = float(os.getenv("RAW_IMAGE_FETCH_TIMEOUT_SECONDS", "15"))
RAW_IMAGE_MAX_ATTACHMENTS = int(os.getenv("RAW_IMAGE_MAX_ATTACHMENTS", "3"))
DEFAULT_MESSAGE_LIMIT = int(os.getenv("DEFAULT_MESSAGE_LIMIT", "20"))
MAX_MESSAGE_LIMIT = int(os.getenv("MAX_MESSAGE_LIMIT", "50"))
DISCORD_HTTP_TIMEOUT_SECONDS = float(os.getenv("DISCORD_HTTP_TIMEOUT_SECONDS", "15"))
MENTION_REPLY_ENABLED = (
    os.getenv("MENTION_REPLY_ENABLED", "0").strip().lower()
    in {"1", "true", "yes", "on"}
)
DISCORD_BOT_USER_ID = os.getenv("DISCORD_BOT_USER_ID", "").strip()
MENTION_REPLY_SCAN_LIMIT = int(os.getenv("MENTION_REPLY_SCAN_LIMIT", "20"))
MENTION_REPLY_LOOKBACK_LIMIT = int(os.getenv("MENTION_REPLY_LOOKBACK_LIMIT", "60"))
MENTION_ACTIVE_MIN_MESSAGES = int(os.getenv("MENTION_ACTIVE_MIN_MESSAGES", "3"))
MENTION_ACTIVE_WINDOW_SECONDS = int(os.getenv("MENTION_ACTIVE_WINDOW_SECONDS", "3600"))
MENTION_REPLY_COOLDOWN_SECONDS = int(os.getenv("MENTION_REPLY_COOLDOWN_SECONDS", "21600"))
MENTION_REPLY_MAX_RESPONSES_PER_RUN = int(
    os.getenv("MENTION_REPLY_MAX_RESPONSES_PER_RUN", "1")
)

ALLOWED_CHANNEL_IDS = {
    channel_id.strip()
    for channel_id in os.getenv("ALLOWED_CHANNEL_IDS", "").split(",")
    if channel_id.strip()
}
# Channels accessible to every authenticated tenant (no per-tenant grant required).
# Useful for shared/announcement channels you want all API consumers to read.
TP_PUBLIC_CHANNEL_IDS = {
    channel_id.strip()
    for channel_id in os.getenv("TP_PUBLIC_CHANNEL_IDS", "").split(",")
    if channel_id.strip()
}

# Multi-tenant rate limiting and API keys (Phase 1)
TP_RATE_LIMIT_PER_MINUTE = int(os.getenv("TP_RATE_LIMIT_PER_MINUTE", "30"))
TP_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("TP_RATE_LIMIT_WINDOW_SECONDS", "60"))
TP_ENABLE_API_KEYS = (
    os.getenv("TP_ENABLE_API_KEYS", "0").strip().lower()
    in {"1", "true", "yes", "on"}
)

# Discord OAuth (Phase 2)
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "").strip()
DISCORD_OAUTH_REDIRECT_URI = os.getenv("DISCORD_OAUTH_REDIRECT_URI", "").strip()
DISCORD_APP_PUBLIC_KEY = os.getenv("DISCORD_APP_PUBLIC_KEY", "").strip().lower()
DISCORD_INTERACTIONS_ENABLED = (
    os.getenv("DISCORD_INTERACTIONS_ENABLED", "1").strip().lower()
    in {"1", "true", "yes", "on"}
)
# View Channel (1024) + Read Message History (65536)
DISCORD_BOT_PERMISSIONS = os.getenv("DISCORD_BOT_PERMISSIONS", "66560").strip()
TP_OAUTH_ENABLED = (
    os.getenv("TP_OAUTH_ENABLED", "0").strip().lower()
    in {"1", "true", "yes", "on"}
)
TP_BASE_URL = os.getenv("TP_BASE_URL", "").strip()
try:
    TP_OAUTH_SHOW_ONCE_TTL_SECONDS = int(
        os.getenv("TP_OAUTH_SHOW_ONCE_TTL_SECONDS", "300")
    )
except ValueError:
    TP_OAUTH_SHOW_ONCE_TTL_SECONDS = 300
TP_OAUTH_SHOW_ONCE_TTL_SECONDS = max(60, min(TP_OAUTH_SHOW_ONCE_TTL_SECONDS, 3600))
try:
    TP_OAUTH_STATE_TTL_SECONDS = int(
        os.getenv(
            "TP_OAUTH_STATE_TTL_SECONDS",
            str(TP_OAUTH_SHOW_ONCE_TTL_SECONDS),
        )
    )
except ValueError:
    TP_OAUTH_STATE_TTL_SECONDS = TP_OAUTH_SHOW_ONCE_TTL_SECONDS
TP_OAUTH_STATE_TTL_SECONDS = max(60, min(TP_OAUTH_STATE_TTL_SECONDS, 3600))

app = Flask(__name__)

# Show-once token store: raw key is held here briefly after OAuth then discarded.
# Maps one-time token -> {raw_key, guild_id, expires_at, pairing_id}
_SHOW_ONCE: dict[str, dict] = {}
# Pairing index for agent-driven Magic Link flow.
# Maps pairing_id -> show_token so /oauth/claim can look up by pairing_id.
_PAIRING_INDEX: dict[str, str] = {}
_LAST_DISCORD_INTERACTION: dict[str, Any] = {}
_LAST_DISCORD_INTERACTION_LOCK = Lock()
RECENT_NONCES: dict[str, int] = {}
MESSAGE_REQUEST_TIMESTAMPS: deque[int] = deque()
MESSAGE_HOST_SEEN_AT: dict[str, int] = {}
MESSAGE_METRICS_LOCK = Lock()
MENTION_REPLIED_AT: dict[str, int] = {}
MENTION_REPLIED_AT_LOCK = Lock()
_BOT_USER_ID_CACHE: str | None = None


@dataclass
class ApiError(Exception):
    """Simple structured API error."""

    message: str
    status_code: int
    debug: dict[str, Any] | None = None


def _error_guidance(error_code: str) -> dict[str, Any] | None:
    """Return safe, actionable guidance for common client errors."""
    if error_code == "invalid_digest":
        return {
            "hint": (
                "tp_digest must be the lowercase hex sha256 of "
                "'{TP_DIGEST_SALT}:{TP_SHARED_SECRET}' (or exactly TP_AGENT_DIGEST when set)."
            ),
            "next_step": (
                "Recompute digest with exact salt/secret bytes (no extra spaces/newlines), "
                "then retry with ?tp_digest=..."
            ),
        }
    if error_code == "missing_digest":
        return {
            "hint": "Provide tp_digest query param (or X-TinyPeople-Digest header).",
            "next_step": "Add ?tp_digest=YOUR_DIGEST to the request URL.",
        }
    if error_code in {"missing_channel_id", "invalid_channel_id"}:
        return {
            "hint": "Provide a numeric Discord channel ID or use discord_url.",
            "next_step": "Example: /messages?channel_id=123... or /messages?discord_url=https://discord.com/channels/GUILD/CHANNEL",
        }
    if error_code == "invalid_discord_url":
        return {
            "hint": "discord_url must be a Discord channel/message link.",
            "next_step": "Use: https://discord.com/channels/GUILD_ID/CHANNEL_ID[/MESSAGE_ID]",
        }
    if error_code.startswith("limit_out_of_range") or error_code == "invalid_limit":
        return {
            "hint": f"limit must be an integer between 1 and {MAX_MESSAGE_LIMIT}.",
            "next_step": "Retry with a valid limit value.",
        }
    if error_code == "invalid_scan_limit":
        return {
            "hint": "scan_limit must be an integer between 1 and 100.",
            "next_step": "Retry with scan_limit=20 (or another value in range).",
        }
    if error_code == "invalid_lookback_limit":
        return {
            "hint": "lookback_limit must be an integer between scan_limit and 200.",
            "next_step": "Retry with lookback_limit=60 (or another value in range).",
        }
    if error_code == "invalid_max_replies":
        return {
            "hint": "max_replies must be an integer between 1 and 3.",
            "next_step": "Retry with max_replies=1.",
        }
    if error_code == "invalid_mention_mode":
        return {
            "hint": "mode must be either query or respond.",
            "next_step": "Retry with mode=query (read-only) or mode=respond (post replies).",
        }
    if error_code == "invalid_embed_mode":
        return {
            "hint": "embed_mode must be either raw or structured.",
            "next_step": "Retry with tp_embed_mode=raw (default) or tp_embed_mode=structured.",
        }
    if error_code == "invalid_message_ids":
        return {
            "hint": "message_ids must be comma-separated numeric Discord message IDs.",
            "next_step": "Retry with message_ids=1234567890,1234567891.",
        }
    if error_code in {"invalid_api_key", "missing_api_key"}:
        return {
            "hint": "Provide a valid tenant key as tp_key (or X-TinyPeople-Key).",
            "next_step": "Run /oauth/authorize to mint a new key, then retry with ?tp_key=...",
        }
    if error_code == "channel_not_allowed_for_tenant":
        return {
            "hint": "This key is valid, but the requested channel is not granted for this tenant.",
            "next_step": "Grant access with /channels/grant?channel_id=... (or add channel to TP_PUBLIC_CHANNEL_IDS).",
        }
    return None


def _resolve_auth_context() -> tuple[Any, bool]:
    """Resolve caller context from request auth material.
    
    Returns (AuthContext or None, is_key_based).
    If using API keys, returns (context, True) and may raise ApiError.
    Otherwise returns (None, False) to fall through to legacy auth.
    """
    if not (get_db and TP_ENABLE_API_KEYS):
        return None, False

    api_key = (
        request.headers.get("X-TinyPeople-Key", "").strip()
        or request.args.get("tp_key", "").strip()
    )
    if not api_key:
        return None, False

    # API key provided; validate it via hash comparison (raw key never stored)
    db = get_db()
    key_info = db.get_api_key_by_raw(api_key)
    if not key_info:
        raise ApiError("invalid_api_key", 403)

    context = AuthContext(
        caller_id=key_info["key_id"],
        tenant_id=key_info["tenant_id"],
        key_id=key_info["key_id"],
        auth_mode="api_key",
    )
    return context, True


def _require_tenant_api_key_context() -> Any:
    """Require a valid tenant-scoped API key and return its auth context."""
    if not (get_db and TP_ENABLE_API_KEYS):
        raise ApiError("api_keys_not_enabled", 503)

    auth_context, is_key_based = _resolve_auth_context()
    if not (auth_context and is_key_based and auth_context.tenant_id and auth_context.key_id):
        raise ApiError("missing_api_key", 401)
    return auth_context


def _debug_requested() -> bool:
    """Return True when debug output is explicitly requested and allowed."""
    if not ALLOW_DEBUG_QUERY_PARAM:
        return False

    raw = request.args.get("tp_debug", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


_DISCORD_CHANNEL_URL_RE = re.compile(
    r"https?://(?:www\.)?discord\.com/channels/(?P<guild>\d+)/(?P<channel>\d+)(?:/(?P<message>\d+))?"
)


def _parse_discord_url(url: str) -> tuple[str, str, str | None] | None:
    """Parse a Discord channel/message URL into (guild_id, channel_id, message_id|None).
    
    Accepts:
      https://discord.com/channels/GUILD/CHANNEL
      https://discord.com/channels/GUILD/CHANNEL/MESSAGE
    Returns None if the URL doesn't match.
    """
    m = _DISCORD_CHANNEL_URL_RE.match(url.strip())
    if not m:
        return None
    return m.group("guild"), m.group("channel"), m.group("message")


def _build_oauth_install_url() -> str | None:
    """Build the Discord bot OAuth install URL, or None if OAuth not configured."""
    if not (DISCORD_CLIENT_ID and DISCORD_OAUTH_REDIRECT_URI):
        return None
    # scope: bot (adds bot to guild) + identify (so we can read installer's identity)
    return (
        f"https://discord.com/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&permissions={DISCORD_BOT_PERMISSIONS}"
        f"&redirect_uri={DISCORD_OAUTH_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=bot+identify"
    )


def _raw_image_mode_requested() -> bool:
    """Return True when caller asks for raw image payloads."""
    mode = request.args.get("tp_image_mode", "").strip().lower()
    if mode == "raw":
        return True

    mode = request.args.get("image_mode", "").strip().lower()
    return mode == "raw"


def _embed_mode_requested() -> str:
    """Return the requested embed mode."""
    mode = request.args.get("tp_embed_mode", "").strip().lower()
    if not mode:
        mode = request.args.get("embed_mode", "").strip().lower()

    if not mode:
        return "raw"

    if mode in {"raw", "structured"}:
        return mode

    raise ApiError("invalid_embed_mode", 400)


def _resolve_secret_from_request() -> str:
    """Get shared secret from supported headers."""
    explicit_secret = request.headers.get("X-TinyPeople-Secret", "").strip()
    if explicit_secret:
        return explicit_secret

    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    if ALLOW_SECRET_QUERY_PARAM:
        # Optional fallback for clients that cannot set custom headers.
        query_secret = request.args.get("tp_secret", "").strip()
        if query_secret:
            return query_secret

    return ""


def _resolve_signed_fields_from_request() -> tuple[str, str, str]:
    """Read signed-auth fields from headers or optional query params."""
    ts = request.headers.get("X-TinyPeople-Timestamp", "").strip()
    nonce = request.headers.get("X-TinyPeople-Nonce", "").strip()
    sig = request.headers.get("X-TinyPeople-Signature", "").strip()

    if ts and nonce and sig:
        return ts, nonce, sig

    if ALLOW_SIGNED_QUERY_PARAM:
        ts = request.args.get("tp_ts", "").strip()
        nonce = request.args.get("tp_nonce", "").strip()
        sig = request.args.get("tp_sig", "").strip()

    return ts, nonce, sig


def _resolve_digest_from_request() -> str:
    """Read static digest token from header or optional query param."""
    digest = request.headers.get("X-TinyPeople-Digest", "").strip()
    if digest:
        return digest

    if ALLOW_STATIC_DIGEST_QUERY_PARAM:
        return request.args.get("tp_digest", "").strip()

    return ""


def _has_signed_auth_material() -> bool:
    """Detect whether signed-auth inputs were supplied."""
    ts, nonce, sig = _resolve_signed_fields_from_request()
    return bool(ts or nonce or sig)


def _prune_old_nonces(now: int) -> None:
    """Drop nonce entries outside the accepted timestamp tolerance window."""
    cutoff = now - SIGNED_TIMESTAMP_TOLERANCE_SECONDS
    stale = [nonce for nonce, ts in RECENT_NONCES.items() if ts < cutoff]
    for nonce in stale:
        RECENT_NONCES.pop(nonce, None)


def _client_ip_from_request() -> str:
    """Resolve client IP, preferring proxy-forwarded headers when present."""
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        first = xff.split(",", 1)[0].strip()
        if first:
            return first

    x_real_ip = request.headers.get("X-Real-IP", "").strip()
    if x_real_ip:
        return x_real_ip

    return request.remote_addr or "unknown"


def _prune_message_metrics(now: int) -> None:
    """Remove stale request timestamps and stale host observations."""
    cutoff = now - METRICS_WINDOW_SECONDS
    while MESSAGE_REQUEST_TIMESTAMPS and MESSAGE_REQUEST_TIMESTAMPS[0] < cutoff:
        MESSAGE_REQUEST_TIMESTAMPS.popleft()

    host_cutoff = now - UNIQUE_HOST_WINDOW_SECONDS
    stale_hosts = [
        host for host, seen_at in MESSAGE_HOST_SEEN_AT.items() if seen_at < host_cutoff
    ]
    for host in stale_hosts:
        MESSAGE_HOST_SEEN_AT.pop(host, None)


def _record_message_request() -> None:
    """Track request volume and unique hosts for /messages endpoint."""
    now = int(time.time())
    host = _client_ip_from_request()
    with MESSAGE_METRICS_LOCK:
        MESSAGE_REQUEST_TIMESTAMPS.append(now)
        MESSAGE_HOST_SEEN_AT[host] = now
        _prune_message_metrics(now)


def _message_metrics_snapshot() -> dict[str, Any]:
    """Return current /messages request telemetry snapshot."""
    now = int(time.time())
    with MESSAGE_METRICS_LOCK:
        _prune_message_metrics(now)
        request_count = len(MESSAGE_REQUEST_TIMESTAMPS)
        rate_per_minute = (request_count * 60.0) / max(METRICS_WINDOW_SECONDS, 1)
        unique_hosts = len(MESSAGE_HOST_SEEN_AT)

    return {
        "requests_in_window": request_count,
        "window_seconds": METRICS_WINDOW_SECONDS,
        "request_rate_per_minute": round(rate_per_minute, 2),
        "unique_hosts_in_window": unique_hosts,
        "unique_hosts_window_seconds": UNIQUE_HOST_WINDOW_SECONDS,
    }


def _build_signature_payload(channel_id: str, limit: int, ts: str, nonce: str) -> str:
    """Build canonical payload used by client and server for HMAC verification."""
    return "\n".join(
        [
            request.method.upper(),
            request.path,
            channel_id,
            str(limit),
            ts,
            nonce,
        ]
    )


def _authorize_static_digest() -> None:
    """Authorize request using a static salted digest token.

    This is intentionally simple for constrained clients that cannot compute
    per-request HMACs. Treat it as a bearer token variant.
    """
    provided = _resolve_digest_from_request()
    if not provided:
        raise ApiError("missing_digest", 401)

    expected = TP_AGENT_DIGEST
    if not expected:
        if not TP_DIGEST_SALT:
            raise ApiError("server_missing_digest_salt", 503)
        expected = hashlib.sha256(
            f"{TP_DIGEST_SALT}:{TP_SHARED_SECRET}".encode("utf-8")
        ).hexdigest()

    normalized = provided.lower().strip()
    looks_sha256_hex = bool(re.fullmatch(r"[0-9a-f]{64}", normalized))
    if not hmac.compare_digest(normalized, expected):
        raise ApiError(
            "invalid_digest",
            403,
            debug={
                "provided_length": len(normalized),
                "looks_sha256_hex": looks_sha256_hex,
                "digest_recipe": "sha256(f'{TP_DIGEST_SALT}:{TP_SHARED_SECRET}')",
                "note": "No secret values are returned here.",
            },
        )


def _authorize_signed_request(channel_id: str, limit: int) -> None:
    """Authorize request via timestamped HMAC signature to avoid raw secret transit."""
    ts_raw, nonce, provided_sig = _resolve_signed_fields_from_request()
    if not ts_raw or not nonce or not provided_sig:
        raise ApiError("missing_signed_auth_fields", 401)

    try:
        ts_value = int(ts_raw)
    except ValueError as exc:
        raise ApiError("invalid_signed_timestamp", 401) from exc

    now = int(time.time())
    if abs(now - ts_value) > SIGNED_TIMESTAMP_TOLERANCE_SECONDS:
        raise ApiError("signed_timestamp_out_of_window", 401)

    _prune_old_nonces(now)
    if nonce in RECENT_NONCES:
        raise ApiError("signed_nonce_reused", 401)

    payload = _build_signature_payload(channel_id, limit, ts_raw, nonce)
    expected_sig = hmac.new(
        TP_SHARED_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(provided_sig.lower(), expected_sig):
        raise ApiError("invalid_signed_signature", 403)

    RECENT_NONCES[nonce] = ts_value


def _authorize_request(channel_id: str, limit: int) -> None:
    """Validate shared secret without exposing sensitive values."""
    if not TP_SHARED_SECRET:
        raise ApiError("server_missing_shared_secret", 503)

    if REQUIRE_SIGNED_AUTH:
        _authorize_signed_request(channel_id, limit)
        return

    digest_candidate = _resolve_digest_from_request()
    if digest_candidate:
        _authorize_static_digest()
        return

    if _has_signed_auth_material():
        _authorize_signed_request(channel_id, limit)
        return

    provided = _resolve_secret_from_request()
    if not provided:
        raise ApiError("missing_shared_secret", 401)

    if not hmac.compare_digest(provided, TP_SHARED_SECRET):
        raise ApiError("invalid_shared_secret", 403)


def _parse_limit(limit_raw: str | None) -> int:
    """Parse and clamp optional message limit."""
    if not limit_raw:
        return DEFAULT_MESSAGE_LIMIT

    try:
        limit = int(limit_raw)
    except ValueError as exc:
        raise ApiError("invalid_limit", 400) from exc

    if limit < 1 or limit > MAX_MESSAGE_LIMIT:
        raise ApiError(f"limit_out_of_range_1_to_{MAX_MESSAGE_LIMIT}", 400)

    return limit


def _parse_bounded_int(
    raw_value: str | None,
    *,
    default: int,
    min_value: int,
    max_value: int,
    error_name: str,
) -> int:
    """Parse an optional integer and constrain it to a configured range."""
    if not raw_value:
        return default

    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ApiError(error_name, 400) from exc

    if value < min_value or value > max_value:
        raise ApiError(error_name, 400)
    return value


def _validate_channel_id(channel_id_raw: str | None) -> str:
    """Validate channel_id parameter and optional allowlist."""
    if not channel_id_raw:
        raise ApiError("missing_channel_id", 400)

    channel_id = channel_id_raw.strip()
    if not channel_id.isdigit():
        raise ApiError("invalid_channel_id", 400)

    if ALLOWED_CHANNEL_IDS and channel_id not in ALLOWED_CHANNEL_IDS:
        raise ApiError("channel_id_not_allowed", 403)

    return channel_id


def _validate_message_id(message_id_raw: str | None) -> str | None:
    """Validate optional message_id query parameter."""
    if not message_id_raw:
        return None

    message_id = message_id_raw.strip()
    if not message_id.isdigit():
        raise ApiError("invalid_message_id", 400)

    return message_id


def _format_author(author: dict[str, Any]) -> str:
    """Normalize Discord author object into stable display name."""
    username = author.get("username", "unknown")
    discriminator = author.get("discriminator", "")
    if discriminator and discriminator != "0":
        return f"{username}#{discriminator}"
    return username


def _chunk_text(value: str, chunk_chars: int) -> list[str]:
    """Split text into deterministic chunks for text-only transport."""
    size = max(chunk_chars, 1)
    return [value[i : i + size] for i in range(0, len(value), size)]


def _build_raw_image_payloads(attachments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fetch image attachments and return chunked base64 payloads."""
    payloads: list[dict[str, Any]] = []
    considered = 0

    for item in attachments:
        if considered >= RAW_IMAGE_MAX_ATTACHMENTS:
            break

        url = str(item.get("url") or "")
        if not url:
            continue

        content_type = str(item.get("content_type") or "")
        has_image_marker = content_type.startswith("image/") or bool(item.get("width"))
        if not has_image_marker:
            continue

        considered += 1
        file_size = int(item.get("size") or 0)
        if file_size and file_size > RAW_IMAGE_MODE_MAX_BYTES:
            payloads.append(
                {
                    "url": url,
                    "filename": str(item.get("filename") or ""),
                    "content_type": content_type,
                    "size_bytes": file_size,
                    "skipped": "file_too_large",
                    "max_bytes": RAW_IMAGE_MODE_MAX_BYTES,
                }
            )
            continue

        try:
            response = requests.get(url, timeout=RAW_IMAGE_FETCH_TIMEOUT_SECONDS)
            response.raise_for_status()
        except requests.RequestException as exc:
            payloads.append(
                {
                    "url": url,
                    "filename": str(item.get("filename") or ""),
                    "content_type": content_type,
                    "error": f"fetch_failed:{type(exc).__name__}",
                }
            )
            continue

        body = response.content
        if len(body) > RAW_IMAGE_MODE_MAX_BYTES:
            payloads.append(
                {
                    "url": url,
                    "filename": str(item.get("filename") or ""),
                    "content_type": response.headers.get("content-type", content_type),
                    "size_bytes": len(body),
                    "skipped": "body_too_large",
                    "max_bytes": RAW_IMAGE_MODE_MAX_BYTES,
                }
            )
            continue

        b64 = base64.b64encode(body).decode("ascii")
        chunks = _chunk_text(b64, RAW_IMAGE_CHUNK_CHARS)
        payloads.append(
            {
                "url": url,
                "filename": str(item.get("filename") or ""),
                "content_type": response.headers.get("content-type", content_type),
                "size_bytes": len(body),
                "encoding": "base64",
                "chunk_chars": RAW_IMAGE_CHUNK_CHARS,
                "chunk_count": len(chunks),
                "chunks": chunks,
            }
        )

    return payloads


def _normalize_embed(embed: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a Discord embed into a compact structured shape."""
    if not isinstance(embed, dict):
        return None

    structured: dict[str, Any] = {}

    for source_key, target_key in (
        ("type", "type"),
        ("title", "title"),
        ("description", "description"),
        ("url", "url"),
        ("timestamp", "timestamp"),
        ("color", "color"),
    ):
        value = embed.get(source_key)
        if isinstance(value, str):
            value = value.strip()
        if value not in (None, ""):
            structured[target_key] = value

    author = embed.get("author")
    if isinstance(author, dict):
        author_name = str(author.get("name") or "").strip()
        if author_name:
            structured["author_name"] = author_name
        author_url = str(author.get("url") or "").strip()
        if author_url:
            structured["author_url"] = author_url
        author_icon_url = str(author.get("icon_url") or "").strip()
        if author_icon_url:
            structured["author_icon_url"] = author_icon_url

    footer = embed.get("footer")
    if isinstance(footer, dict):
        footer_text = str(footer.get("text") or "").strip()
        if footer_text:
            structured["footer_text"] = footer_text
        footer_icon_url = str(footer.get("icon_url") or "").strip()
        if footer_icon_url:
            structured["footer_icon_url"] = footer_icon_url

    for source_key, target_key in (("image", "image_url"), ("thumbnail", "thumbnail_url"), ("video", "video_url")):
        nested = embed.get(source_key)
        if isinstance(nested, dict):
            nested_url = str(nested.get("url") or "").strip()
            if nested_url:
                structured[target_key] = nested_url

    raw_fields = embed.get("fields")
    structured_fields: list[dict[str, Any]] = []
    if isinstance(raw_fields, list):
        for field in raw_fields:
            if not isinstance(field, dict):
                continue
            field_name = str(field.get("name") or "").strip()
            field_value = str(field.get("value") or "").strip()
            if not field_name and not field_value:
                continue
            structured_fields.append(
                {
                    "name": field_name,
                    "value": field_value,
                    "inline": bool(field.get("inline")),
                }
            )
    if structured_fields:
        structured["fields"] = structured_fields

    return structured or None


def _normalize_message(
    message: dict[str, Any], *, include_raw_images: bool = False, embed_mode: str = "raw"
) -> dict[str, Any]:
    """Convert Discord message payload to contract output shape."""
    content = message.get("content", "")
    raw_attachments = message.get("attachments")
    attachments = raw_attachments if isinstance(raw_attachments, list) else []
    raw_embeds = message.get("embeds")
    embeds = raw_embeds if isinstance(raw_embeds, list) else []
    attachment_urls = [
        str(item.get("url"))
        for item in attachments
        if isinstance(item, dict) and item.get("url")
    ]
    image_urls = [
        str(item.get("url"))
        for item in attachments
        if isinstance(item, dict)
        and item.get("url")
        and (str(item.get("content_type", "")).startswith("image/") or item.get("width"))
    ]

    embed_summaries = []
    for embed in embeds:
        if not isinstance(embed, dict):
            continue
        title = str(embed.get("title") or "").strip()
        description = str(embed.get("description") or "").strip()
        summary = " - ".join(part for part in (title, description) if part)
        if summary:
            embed_summaries.append(summary)

    # Preserve signal for non-text entries while keeping the response compact.
    if not content and embed_summaries:
        content = " | ".join(embed_summaries)
    elif not content and attachments:
        content = "[attachment]"

    if embed_mode == "structured":
        normalized_embeds = [item for item in (_normalize_embed(embed) for embed in embeds) if item]
    else:
        normalized_embeds = embeds

    normalized = {
        "timestamp": message.get("timestamp"),
        "message_id": message.get("id"),
        "author": _format_author(message.get("author", {})),
        "content": content,
        "attachment_urls": attachment_urls,
        "image_urls": image_urls,
        "embeds": normalized_embeds,
    }

    if include_raw_images:
        normalized["raw_images"] = _build_raw_image_payloads(attachments)

    return normalized


def _fetch_discord_message_by_id(
    channel_id: str,
    message_id: str,
    *,
    include_raw_images: bool = False,
    embed_mode: str = "raw",
) -> dict[str, Any]:
    """Read one specific message from Discord REST API by message ID."""
    if not DISCORD_TOKEN:
        raise ApiError("server_missing_discord_token", 503)

    url = f"https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}"
    headers = {
        "Authorization": f"Bot {DISCORD_TOKEN}",
        "User-Agent": "tinyPeople-messages-api/0.1.0",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=DISCORD_HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise ApiError(
            "discord_upstream_unreachable",
            502,
            debug={"upstream": "discord", "exception": type(exc).__name__},
        ) from exc

    response_body_json: Any | None = None
    try:
        response_body_json = response.json()
    except ValueError:
        response_body_json = None

    if response.status_code == 401:
        raise ApiError(
            "discord_token_rejected",
            502,
            debug={"discord_status": 401},
        )
    if response.status_code == 403:
        debug = {"discord_status": 403}
        if isinstance(response_body_json, dict):
            debug["discord_code"] = response_body_json.get("code")
            debug["discord_message"] = response_body_json.get("message")
        raise ApiError("discord_forbidden_channel", 403, debug=debug)
    if response.status_code == 404:
        debug = {"discord_status": 404}
        if isinstance(response_body_json, dict):
            debug["discord_code"] = response_body_json.get("code")
            debug["discord_message"] = response_body_json.get("message")
        raise ApiError("discord_message_not_found", 404, debug=debug)
    if response.status_code >= 400:
        debug = {"discord_status": response.status_code}
        if isinstance(response_body_json, dict):
            debug["discord_code"] = response_body_json.get("code")
            debug["discord_message"] = response_body_json.get("message")
        raise ApiError("discord_upstream_error", 502, debug=debug)

    if not isinstance(response_body_json, dict):
        raise ApiError(
            "discord_unexpected_payload",
            502,
            debug={"discord_status": response.status_code, "payload_type": type(response_body_json).__name__},
        )

    return _normalize_message(
        response_body_json,
        include_raw_images=include_raw_images,
        embed_mode=embed_mode,
    )


def _fetch_discord_messages(
    channel_id: str,
    limit: int,
    *,
    include_raw_images: bool = False,
    embed_mode: str = "raw",
) -> list[dict[str, Any]]:
    """Read message history from Discord REST API."""
    if not DISCORD_TOKEN:
        raise ApiError("server_missing_discord_token", 503)

    url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
    headers = {
        "Authorization": f"Bot {DISCORD_TOKEN}",
        "User-Agent": "tinyPeople-messages-api/0.1.0",
    }
    params = {"limit": limit}

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=DISCORD_HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise ApiError(
            "discord_upstream_unreachable",
            502,
            debug={"upstream": "discord", "exception": type(exc).__name__},
        ) from exc

    response_body_json: Any | None = None
    try:
        response_body_json = response.json()
    except ValueError:
        response_body_json = None

    if response.status_code == 401:
        raise ApiError(
            "discord_token_rejected",
            502,
            debug={"discord_status": 401},
        )
    if response.status_code == 403:
        debug = {"discord_status": 403}
        if isinstance(response_body_json, dict):
            debug["discord_code"] = response_body_json.get("code")
            debug["discord_message"] = response_body_json.get("message")
        raise ApiError("discord_forbidden_channel", 403, debug=debug)
    if response.status_code == 404:
        debug = {"discord_status": 404}
        if isinstance(response_body_json, dict):
            debug["discord_code"] = response_body_json.get("code")
            debug["discord_message"] = response_body_json.get("message")
        raise ApiError("discord_channel_not_found", 404, debug=debug)
    if response.status_code >= 400:
        debug = {"discord_status": response.status_code}
        if isinstance(response_body_json, dict):
            debug["discord_code"] = response_body_json.get("code")
            debug["discord_message"] = response_body_json.get("message")
        raise ApiError("discord_upstream_error", 502, debug=debug)

    data = response_body_json
    if not isinstance(data, list):
        raise ApiError(
            "discord_unexpected_payload",
            502,
            debug={"discord_status": response.status_code, "payload_type": type(data).__name__},
        )

    return [
        _normalize_message(msg, include_raw_images=include_raw_images, embed_mode=embed_mode)
        for msg in data
    ]


def _fetch_discord_messages_raw(channel_id: str, limit: int) -> list[dict[str, Any]]:
    """Read raw Discord message payloads for mention/status workflows."""
    if not DISCORD_TOKEN:
        raise ApiError("server_missing_discord_token", 503)

    url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
    headers = {
        "Authorization": f"Bot {DISCORD_TOKEN}",
        "User-Agent": "tinyPeople-messages-api/0.1.0",
    }
    remaining = max(1, limit)
    before_message_id = ""
    collected: list[dict[str, Any]] = []

    while remaining > 0:
        page_size = min(remaining, 100)
        params: dict[str, Any] = {"limit": page_size}
        if before_message_id:
            params["before"] = before_message_id

        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=DISCORD_HTTP_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            raise ApiError(
                "discord_upstream_unreachable",
                502,
                debug={"upstream": "discord", "exception": type(exc).__name__},
            ) from exc

        response_body_json: Any | None = None
        try:
            response_body_json = response.json()
        except ValueError:
            response_body_json = None

        if response.status_code == 401:
            raise ApiError("discord_token_rejected", 502, debug={"discord_status": 401})
        if response.status_code == 403:
            debug = {"discord_status": 403}
            if isinstance(response_body_json, dict):
                debug["discord_code"] = response_body_json.get("code")
                debug["discord_message"] = response_body_json.get("message")
            raise ApiError("discord_forbidden_channel", 403, debug=debug)
        if response.status_code == 404:
            debug = {"discord_status": 404}
            if isinstance(response_body_json, dict):
                debug["discord_code"] = response_body_json.get("code")
                debug["discord_message"] = response_body_json.get("message")
            raise ApiError("discord_channel_not_found", 404, debug=debug)
        if response.status_code >= 400:
            debug = {"discord_status": response.status_code}
            if isinstance(response_body_json, dict):
                debug["discord_code"] = response_body_json.get("code")
                debug["discord_message"] = response_body_json.get("message")
            raise ApiError("discord_upstream_error", 502, debug=debug)

        if not isinstance(response_body_json, list):
            raise ApiError(
                "discord_unexpected_payload",
                502,
                debug={"discord_status": response.status_code, "payload_type": type(response_body_json).__name__},
            )

        page_items = [item for item in response_body_json if isinstance(item, dict)]
        collected.extend(page_items)
        remaining -= len(page_items)

        if not page_items or len(page_items) < page_size:
            break

        last_id = str(page_items[-1].get("id", "")).strip()
        if not last_id:
            break
        before_message_id = last_id

    return collected[:limit]


def _fetch_discord_bot_user_id() -> str:
    """Resolve the bot account user ID, using env override then Discord /users/@me."""
    global _BOT_USER_ID_CACHE
    if DISCORD_BOT_USER_ID:
        return DISCORD_BOT_USER_ID
    if _BOT_USER_ID_CACHE:
        return _BOT_USER_ID_CACHE

    if not DISCORD_TOKEN:
        raise ApiError("server_missing_discord_token", 503)

    try:
        response = requests.get(
            "https://discord.com/api/v10/users/@me",
            headers={
                "Authorization": f"Bot {DISCORD_TOKEN}",
                "User-Agent": "tinyPeople-messages-api/0.1.0",
            },
            timeout=DISCORD_HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise ApiError(
            "discord_upstream_unreachable",
            502,
            debug={"upstream": "discord", "exception": type(exc).__name__},
        ) from exc

    data: Any | None = None
    try:
        data = response.json()
    except ValueError:
        data = None

    if response.status_code >= 400:
        raise ApiError("discord_bot_identity_unavailable", 502, debug={"discord_status": response.status_code})
    if not isinstance(data, dict) or not str(data.get("id", "")).strip().isdigit():
        raise ApiError("discord_bot_identity_unavailable", 502)

    _BOT_USER_ID_CACHE = str(data["id"]).strip()
    return _BOT_USER_ID_CACHE


def _discord_iso_age_seconds(iso_ts: str) -> int | None:
    """Convert Discord ISO timestamp to seconds elapsed from now."""
    if not iso_ts:
        return None
    try:
        parsed = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    now_utc = datetime.now(timezone.utc)
    delta = now_utc - parsed
    return max(0, int(delta.total_seconds()))


def _message_mentions_bot(message: dict[str, Any], bot_user_id: str) -> bool:
    """Check whether a Discord message mentions this bot account."""
    mentions = message.get("mentions")
    if isinstance(mentions, list):
        for mention in mentions:
            if not isinstance(mention, dict):
                continue
            if str(mention.get("id", "")).strip() == bot_user_id:
                return True

    content = str(message.get("content") or "")
    return f"<@{bot_user_id}>" in content or f"<@!{bot_user_id}>" in content


def _bot_already_replied_to_message(
    *,
    mention_message_id: str,
    bot_user_id: str,
    channel_history: list[dict[str, Any]],
) -> bool:
    """Check channel history for an existing bot reply tied to the mention message.

    This survives process restarts because the signal is in Discord history,
    not local in-memory cooldown state.
    """
    for item in channel_history:
        author = item.get("author") if isinstance(item.get("author"), dict) else {}
        if str(author.get("id", "")).strip() != bot_user_id:
            continue

        reference = (
            item.get("message_reference")
            if isinstance(item.get("message_reference"), dict)
            else {}
        )
        referenced_id = str(reference.get("message_id", "")).strip()
        if referenced_id and referenced_id == mention_message_id:
            return True

    return False


def _prune_mention_replied_cache(now: int) -> None:
    """Drop mention IDs outside cooldown window to avoid unbounded memory usage."""
    cutoff = now - MENTION_REPLY_COOLDOWN_SECONDS
    stale = [message_id for message_id, ts in MENTION_REPLIED_AT.items() if ts < cutoff]
    for message_id in stale:
        MENTION_REPLIED_AT.pop(message_id, None)


def _is_mention_replied(message_id: str) -> bool:
    """Return True when this mention message was already handled recently."""
    now = int(time.time())
    with MENTION_REPLIED_AT_LOCK:
        _prune_mention_replied_cache(now)
        return message_id in MENTION_REPLIED_AT


def _mark_mention_replied(message_id: str) -> None:
    """Mark mention message as handled to prevent duplicate bot replies."""
    now = int(time.time())
    with MENTION_REPLIED_AT_LOCK:
        _prune_mention_replied_cache(now)
        MENTION_REPLIED_AT[message_id] = now


def _build_user_activity_status(
    user_id: str,
    channel_history: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build an activity snapshot for a user based on recent channel history."""
    user_messages = [
        msg
        for msg in channel_history
        if isinstance(msg.get("author"), dict)
        and str(msg["author"].get("id", "")).strip() == user_id
    ]
    message_count = len(user_messages)
    latest_timestamp = str(user_messages[0].get("timestamp") or "") if user_messages else ""
    latest_age_seconds = _discord_iso_age_seconds(latest_timestamp) if latest_timestamp else None
    is_active = (
        message_count >= MENTION_ACTIVE_MIN_MESSAGES
        and latest_age_seconds is not None
        and latest_age_seconds <= MENTION_ACTIVE_WINDOW_SECONDS
    )

    return {
        "user_id": user_id,
        "message_count_in_lookback": message_count,
        "lookback_messages": len(channel_history),
        "latest_message_age_seconds": latest_age_seconds,
        "active": is_active,
        "active_threshold": {
            "min_messages": MENTION_ACTIVE_MIN_MESSAGES,
            "window_seconds": MENTION_ACTIVE_WINDOW_SECONDS,
        },
    }


def _build_recent_message_preview(
    user_id: str,
    mention_message_id: str,
    channel_history: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return one recent prior message for quick context, if available."""
    for item in channel_history:
        if not isinstance(item, dict):
            continue
        author = item.get("author") if isinstance(item.get("author"), dict) else {}
        if str(author.get("id", "")).strip() != user_id:
            continue

        message_id = str(item.get("id", "")).strip()
        if not message_id or message_id == mention_message_id:
            continue

        return {
            "message_id": message_id,
            "content": str(item.get("content") or ""),
            "timestamp": str(item.get("timestamp") or ""),
        }

    return None


def _collect_mention_candidates(
    channel_id: str,
    scan_limit: int,
    lookback_limit: int,
) -> dict[str, Any]:
    """Collect mention candidates and reply-eligibility metadata without posting."""
    recent_for_mentions = _fetch_discord_messages_raw(channel_id, scan_limit)
    history = _fetch_discord_messages_raw(channel_id, lookback_limit)
    bot_user_id = _fetch_discord_bot_user_id()

    # Discord returns newest-first; process oldest-first for natural reply order.
    ordered_messages = list(reversed(recent_for_mentions))
    candidates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for message in ordered_messages:
        message_id = str(message.get("id", "")).strip()
        if not message_id:
            continue

        author = message.get("author") if isinstance(message.get("author"), dict) else {}
        author_id = str(author.get("id", "")).strip()
        if not author_id or author_id == bot_user_id:
            continue

        if not _message_mentions_bot(message, bot_user_id):
            continue

        already_replied_in_history = _bot_already_replied_to_message(
            mention_message_id=message_id,
            bot_user_id=bot_user_id,
            channel_history=history,
        )
        already_replied_recently = _is_mention_replied(message_id)

        reason = None
        if already_replied_in_history:
            reason = "already_replied_in_history"
        elif already_replied_recently:
            reason = "already_replied_recently"

        if reason:
            skipped.append({"message_id": message_id, "reason": reason})

        candidates.append(
            {
                "message_id": message_id,
                "user_id": author_id,
                "mention_content": str(message.get("content") or ""),
                "timestamp": str(message.get("timestamp") or ""),
                "author": {
                    "username": str(author.get("username") or ""),
                    "global_name": str(author.get("global_name") or ""),
                    "display_name": str(author.get("display_name") or ""),
                },
                "activity_status": _build_user_activity_status(author_id, history),
                "reply_eligible": not (already_replied_in_history or already_replied_recently),
                "already_replied_in_history": already_replied_in_history,
                "already_replied_recently": already_replied_recently,
            }
        )

    return {
        "history": history,
        "bot_user_id": bot_user_id,
        "candidates": candidates,
        "skipped": skipped,
    }


def _build_activity_reply_text(status: dict[str, Any]) -> str:
    """Build default activity summary text without mention prefix."""

    def _plural(value: int, singular: str, plural: str) -> str:
        return singular if value == 1 else plural

    def _human_duration(seconds: int | None) -> str:
        if seconds is None:
            return "unknown time"
        if seconds < 60:
            return f"{seconds} {_plural(seconds, 'second', 'seconds')}"
        if seconds < 3600:
            minutes = max(1, seconds // 60)
            return f"{minutes} {_plural(minutes, 'minute', 'minutes')}"
        if seconds < 86400:
            hours = max(1, seconds // 3600)
            return f"{hours} {_plural(hours, 'hour', 'hours')}"
        days = max(1, seconds // 86400)
        return f"{days} {_plural(days, 'day', 'days')}"

    message_count = int(status.get("message_count_in_lookback", 0))
    lookback_messages = int(status.get("lookback_messages", 0))
    latest_age_seconds = status.get("latest_message_age_seconds")
    active = bool(status.get("active", False))
    min_messages = int(status.get("active_threshold", {}).get("min_messages", MENTION_ACTIVE_MIN_MESSAGES))
    window_seconds = int(status.get("active_threshold", {}).get("window_seconds", MENTION_ACTIVE_WINDOW_SECONDS))

    if active:
        if isinstance(latest_age_seconds, int) and latest_age_seconds <= 300:
            status_text = (
                f"Loud and clear. You are definitely active right now - "
                f"{message_count} recent {_plural(message_count, 'message', 'messages')} from you."
            )
        else:
            recency = _human_duration(latest_age_seconds if isinstance(latest_age_seconds, int) else None)
            status_text = (
                f"I hear you. You are active here - I can see {message_count} recent "
                f"{_plural(message_count, 'message', 'messages')} and your latest was about {recency} ago."
            )
    else:
        hour_window = _human_duration(window_seconds)
        inactive_variants = [
            (
                f"I hear you. You have only sent a couple messages recently though - "
                f"I was starting to think you were lurking. "
                f"({message_count} in the last {lookback_messages} messages.)"
            ),
            (
                f"Loud and clear. Was starting to wonder if you had gone quiet though - "
                f"only {message_count} {_plural(message_count, 'message', 'messages')} "
                f"from you in the last {hour_window} keeps you under my chatter threshold."
            ),
            (
                f"Yeah, I see you. Barely. {message_count} "
                f"{_plural(message_count, 'message', 'messages')} in the last {hour_window} "
                "does not exactly scream active."
            ),
        ]
        variant_index = message_count % len(inactive_variants)
        status_text = inactive_variants[variant_index]

    threshold_text = (
        f"Threshold: {min_messages}+ {_plural(min_messages, 'message', 'messages')} "
        f"within {_human_duration(window_seconds)}."
    )

    return f"{status_text} {threshold_text}"


def _compose_reply_content(user_id: str, status: dict[str, Any], custom_reply_message: str = "") -> str:
    """Compose reply content, using caller-authored text when provided."""
    custom_text = custom_reply_message.strip()
    if custom_text:
        if f"<@{user_id}>" in custom_text or f"<@!{user_id}>" in custom_text:
            return custom_text
        return f"<@{user_id}> {custom_text}"

    return f"<@{user_id}> {_build_activity_reply_text(status)}"


def _post_discord_message_reply(
    channel_id: str,
    reference_message_id: str,
    user_id: str,
    status: dict[str, Any],
    custom_reply_message: str = "",
) -> None:
    """Post a Discord threaded reply describing the caller's recent activity."""
    if not DISCORD_TOKEN:
        raise ApiError("server_missing_discord_token", 503)

    content = _compose_reply_content(user_id, status, custom_reply_message=custom_reply_message)

    try:
        response = requests.post(
            f"https://discord.com/api/v10/channels/{channel_id}/messages",
            headers={
                "Authorization": f"Bot {DISCORD_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "content": content,
                "message_reference": {
                    "message_id": reference_message_id,
                    "channel_id": channel_id,
                },
                "allowed_mentions": {
                    "parse": [],
                    "users": [user_id],
                    "replied_user": True,
                },
            },
            timeout=DISCORD_HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise ApiError(
            "discord_upstream_unreachable",
            502,
            debug={"upstream": "discord", "exception": type(exc).__name__},
        ) from exc

    if response.status_code >= 400:
        details: dict[str, Any] = {}
        try:
            body = response.json()
            if isinstance(body, dict):
                details = {
                    "discord_code": body.get("code"),
                    "discord_message": body.get("message"),
                }
        except ValueError:
            details = {}

        raise ApiError(
            "discord_reply_failed",
            502,
            debug={"discord_status": response.status_code, **details},
        )


@app.route("/")
def home() -> tuple[Any, int]:
    """Operator-facing status endpoint."""
    help_url = f"{request.url_root.rstrip('/')}/help"
    return (
        jsonify(
            {
                "service": "tinyPeople Discord Messages API",
                "status": "alive",
                "version": BOT_VERSION,
                "revision": APP_REVISION,
                "build": APP_BUILD,
                "runtime_signature": APP_RUNTIME_SIGNATURE,
                "help_url": help_url,
            }
        ),
        200,
    )


@app.route("/help")
def help_text() -> tuple[Any, int]:
    """Plain-text quickstart guide for human operators and agents."""
    base_url = TP_BASE_URL or request.url_root.rstrip("/")
    text = _build_help_text(base_url)
    return Response(text + "\n", mimetype="text/plain"), 200


def _build_help_text(base_url: str) -> str:
    """Build plain-text operator/agent help text for HTTP and slash command use."""
    sample_pairing = "tp-pair-example-001"
    sample_url = (
        "https%3A%2F%2Fdiscord.com%2Fchannels%2F"
        "269789046635495424%2F355261872024453130%2F1492491000873222225"
    )

    text = "\n".join(
        [
            "tinyPeople Discord Messages API help",
            "",
            "Quick Start for Humans:",
            "Just click the magic link your tinyPeople agent gives you, approve the connection in Discord",
            "(you choose which servers/channels it can see), and you will get a personal tp_key in seconds.",
            "No bot tokens or developer portal needed. Use that key to fetch messages.",
            "Try it now: ask your tinyNature for a pairing link and you are good to go.",
            "",
            "Magic Link flow:",
            "1) Agent generates a random pairing_id (example shown) and starts pairing:",
            f"{base_url}/oauth/authorize?pairing_id={sample_pairing}",
            "2) User opens authorize_url from response and approves OAuth in Discord.",
            "3) Agent claims key using the same pairing_id (no tp_digest or tp_key required):",
            f"{base_url}/oauth/claim?pairing_id={sample_pairing}",
            "4) Claim response returns api_key. Use that value as tp_key on /messages and channel-policy routes.",
            "",
            "Optional tenant channel policy endpoints (after claim, use tp_key):",
            f"{base_url}/channels/list?tp_key=YOUR_KEY",
            "Use /channels/list first to see channels this key can access (public + tenant grants).",
            f"{base_url}/channels/grant?channel_id=355261872024453130&tp_key=YOUR_KEY",
            f"{base_url}/channels/revoke?channel_id=355261872024453130&tp_key=YOUR_KEY",
            "",
            "Message fetch examples:",
            f"{base_url}/messages?channel_id=355261872024453130&message_id=1492491000873222225&tp_key=YOUR_KEY",
            f"{base_url}/messages?discord_url={sample_url}&tp_key=YOUR_KEY",
            f"{base_url}/messages?discord_url={sample_url}&tp_key=YOUR_KEY&tp_debug=1",
            "",
            "Affirm-reply (human-gated; nothing sends until you approve):",
            f"{base_url}/discord/replies/propose?channel_id=CHANNEL_ID&message_id=MESSAGE_ID&reply_message=TEXT&tp_key=YOUR_KEY",
            f"{base_url}/discord/replies/approve?proposal_id=PROPOSAL_ID&tp_key=YOUR_KEY",
            f"{base_url}/discord/replies/approve?proposal_id=PROPOSAL_ID&confirm=1&tp_key=YOUR_KEY",
            "Health endpoint:",
            f"{base_url}/health",
        ]
    )

    return text


def _discord_signature_is_valid(raw_body: bytes) -> bool:
    """Validate Discord interaction signature headers against raw request body."""
    if not (VerifyKey and DISCORD_APP_PUBLIC_KEY):
        return False

    signature = request.headers.get("X-Signature-Ed25519", "").strip()
    timestamp = request.headers.get("X-Signature-Timestamp", "").strip()
    if not signature or not timestamp:
        return False

    try:
        verify_key = VerifyKey(bytes.fromhex(DISCORD_APP_PUBLIC_KEY))
        verify_key.verify(timestamp.encode("utf-8") + raw_body, bytes.fromhex(signature))
        return True
    except (BadSignatureError, ValueError):
        return False


@app.route("/discord/interactions", methods=["GET", "HEAD", "OPTIONS", "POST"])
def discord_interactions() -> tuple[Any, int]:
    """Handle Discord HTTP interactions (PING and /help slash command)."""
    if not DISCORD_INTERACTIONS_ENABLED:
        return jsonify({"error": "discord_interactions_disabled"}), 503

    if request.method in {"GET", "HEAD", "OPTIONS"}:
        with _LAST_DISCORD_INTERACTION_LOCK:
            _LAST_DISCORD_INTERACTION.clear()
            _LAST_DISCORD_INTERACTION.update(
                {
                    "ts": int(time.time()),
                    "status": "probe",
                    "method": request.method,
                    "content_type": request.headers.get("Content-Type", ""),
                    "user_agent": request.headers.get("User-Agent", ""),
                    "has_sig_header": bool(request.headers.get("X-Signature-Ed25519", "").strip()),
                    "has_ts_header": bool(request.headers.get("X-Signature-Timestamp", "").strip()),
                }
            )
        return jsonify({"status": "ok", "endpoint": "discord_interactions"}), 200

    raw_body = request.get_data(cache=False, as_text=False)
    decoded_body = raw_body.decode("utf-8", errors="replace") if raw_body else ""
    try:
        payload = json.loads(decoded_body) if raw_body else {}
    except (ValueError, UnicodeDecodeError):
        with _LAST_DISCORD_INTERACTION_LOCK:
            _LAST_DISCORD_INTERACTION.clear()
            _LAST_DISCORD_INTERACTION.update(
                {
                    "ts": int(time.time()),
                    "status": "invalid_payload",
                    "content_type": request.headers.get("Content-Type", ""),
                    "user_agent": request.headers.get("User-Agent", ""),
                    "has_sig_header": bool(request.headers.get("X-Signature-Ed25519", "").strip()),
                    "has_ts_header": bool(request.headers.get("X-Signature-Timestamp", "").strip()),
                    "body_preview": decoded_body[:300],
                }
            )
        return jsonify({"error": "invalid_interaction_payload"}), 400

    itype = payload.get("type")
    signature_valid = _discord_signature_is_valid(raw_body)
    with _LAST_DISCORD_INTERACTION_LOCK:
        _LAST_DISCORD_INTERACTION.clear()
        _LAST_DISCORD_INTERACTION.update(
            {
                "ts": int(time.time()),
                "status": "received",
                "type": itype,
                "content_type": request.headers.get("Content-Type", ""),
                "user_agent": request.headers.get("User-Agent", ""),
                "has_sig_header": bool(request.headers.get("X-Signature-Ed25519", "").strip()),
                "has_ts_header": bool(request.headers.get("X-Signature-Timestamp", "").strip()),
                "signature_valid": signature_valid,
                "body_preview": decoded_body[:300],
            }
        )

    # Discord interaction verification handshake.
    if itype in {1, "1"}:
        # Keep this path permissive so endpoint verification can succeed even
        # before signature config is fully wired.
        return jsonify({"type": 1}), 200

    if not signature_valid:
        return jsonify({"error": "invalid_discord_signature"}), 401

    # Slash command invocation.
    if itype == 2:
        command = (payload.get("data") or {}).get("name", "")
        if command == "help":
            base_url = TP_BASE_URL or request.url_root.rstrip("/")
            content = _build_help_text(base_url)
            # Discord message content limit is 2000 chars.
            if len(content) > 1900:
                content = (
                    "tinyPeople help:\n"
                    f"{base_url}/help\n"
                    "Use the /help endpoint for full plain-text instructions."
                )
            return jsonify({"type": 4, "data": {"content": content}}), 200

        return jsonify({"type": 4, "data": {"content": "Unknown command."}}), 200

    return jsonify({"error": "unsupported_interaction_type"}), 400


@app.route("/discord/interactions/health", methods=["GET"])
def discord_interactions_health() -> tuple[Any, int]:
    """Minimal diagnostics for Discord interactions config (no secret leakage)."""
    key_is_hex_64 = bool(re.fullmatch(r"[0-9a-f]{64}", DISCORD_APP_PUBLIC_KEY))
    return jsonify(
        {
            "status": "ok",
            "interactions_enabled": DISCORD_INTERACTIONS_ENABLED,
            "verify_library_loaded": bool(VerifyKey),
            "public_key_configured": bool(DISCORD_APP_PUBLIC_KEY),
            "public_key_is_64_hex": key_is_hex_64,
            "endpoint_url": f"{TP_BASE_URL or request.url_root.rstrip('/')}/discord/interactions",
        }
    ), 200


@app.route("/discord/interactions/last", methods=["GET"])
def discord_interactions_last() -> tuple[Any, int]:
    """Show last interaction request seen by endpoint (operator auth required)."""
    try:
        _authorize_static_digest()
    except ApiError as exc:
        return jsonify({"error": exc.message, **(_error_guidance(exc.message) or {})}), exc.status_code

    with _LAST_DISCORD_INTERACTION_LOCK:
        payload = dict(_LAST_DISCORD_INTERACTION)

    if not payload:
        return jsonify({"status": "no_interactions_seen"}), 200
    return jsonify(payload), 200


@app.route("/discord/commands/sync", methods=["GET"])
def discord_commands_sync() -> tuple[Any, int]:
    """Register global slash commands for this app (operator digest auth required)."""
    try:
        _authorize_static_digest()
    except ApiError as exc:
        return jsonify({"error": exc.message, **(_error_guidance(exc.message) or {})}), exc.status_code

    if not (DISCORD_TOKEN and DISCORD_CLIENT_ID):
        return jsonify({"error": "discord_command_sync_not_configured"}), 503

    commands = [
        {
            "name": "help",
            "description": "Show tinyPeople API help links",
        }
    ]

    try:
        resp = requests.put(
            f"https://discord.com/api/v10/applications/{DISCORD_CLIENT_ID}/commands",
            headers={
                "Authorization": f"Bot {DISCORD_TOKEN}",
                "Content-Type": "application/json",
            },
            json=commands,
            timeout=10,
        )
    except requests.RequestException as exc:
        return jsonify({"error": f"discord_command_sync_failed: {type(exc).__name__}"}), 502

    if resp.status_code >= 400:
        details = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        return jsonify(
            {
                "error": "discord_command_sync_failed",
                "discord_status": resp.status_code,
                "discord_message": details.get("message"),
                "discord_code": details.get("code"),
            }
        ), 502

    registered = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else []
    return jsonify(
        {
            "status": "ok",
            "registered_commands": [item.get("name") for item in registered if isinstance(item, dict)],
            "count": len(registered) if isinstance(registered, list) else 0,
            "interactions_url_hint": f"{TP_BASE_URL or request.url_root.rstrip('/')}/discord/interactions",
        }
    ), 200


@app.route("/discord/mentions/respond", methods=["GET"])
def discord_mentions_respond() -> tuple[Any, int]:
    """Query or reply to recent bot mentions with optional caller-authored text."""
    if not MENTION_REPLY_ENABLED:
        return jsonify({"error": "mention_reply_disabled"}), 503

    channel_id = None
    try:
        auth_context, is_key_based = _resolve_auth_context()
        channel_id = _validate_channel_id(request.args.get("channel_id"))

        if not is_key_based:
            _authorize_request(channel_id, 1)

        if auth_context and auth_context.tenant_id and get_db:
            db = get_db()
            if (
                channel_id not in TP_PUBLIC_CHANNEL_IDS
                and not db.is_channel_allowed_for_tenant(auth_context.tenant_id, channel_id)
            ):
                raise ApiError("channel_not_allowed_for_tenant", 403)

        scan_limit = _parse_bounded_int(
            request.args.get("scan_limit"),
            default=min(max(1, MENTION_REPLY_SCAN_LIMIT), 100),
            min_value=1,
            max_value=100,
            error_name="invalid_scan_limit",
        )

        lookback_limit = _parse_bounded_int(
            request.args.get("lookback_limit"),
            default=min(max(MENTION_REPLY_LOOKBACK_LIMIT, scan_limit), 200),
            min_value=max(1, scan_limit),
            max_value=200,
            error_name="invalid_lookback_limit",
        )

        max_replies_raw = request.args.get("max_replies", "").strip()
        if max_replies_raw:
            try:
                max_replies = int(max_replies_raw)
            except ValueError as exc:
                raise ApiError("invalid_max_replies", 400) from exc
        else:
            max_replies = MENTION_REPLY_MAX_RESPONSES_PER_RUN
        max_replies = max(1, min(max_replies, 3))

        mode = request.args.get("mode", "respond").strip().lower()
        if mode not in {"query", "respond"}:
            raise ApiError("invalid_mention_mode", 400)

        reply_message = request.args.get("reply_message", "")

        message_id_tokens: list[str] = []
        for raw_value in request.args.getlist("message_ids"):
            for token in raw_value.split(","):
                candidate = token.strip()
                if not candidate:
                    continue
                if not candidate.isdigit():
                    raise ApiError("invalid_message_ids", 400)
                message_id_tokens.append(candidate)
        target_message_ids = set(message_id_tokens)

        scan_result = _collect_mention_candidates(channel_id, scan_limit, lookback_limit)
        candidates = scan_result["candidates"]
        skipped: list[dict[str, Any]] = list(scan_result["skipped"])

        if mode == "query":
            most_recent_mention: dict[str, Any] | None = None
            if candidates:
                newest = candidates[-1]
                recent_preview = _build_recent_message_preview(
                    newest["user_id"],
                    newest["message_id"],
                    scan_result["history"],
                )
                most_recent_mention = {
                    "message_id": newest["message_id"],
                    "recent_message_preview": recent_preview,
                }

            return jsonify(
                {
                    "status": "ok",
                    "mode": "query",
                    "channel_id": channel_id,
                    "scan_limit": scan_limit,
                    "lookback_limit": lookback_limit,
                    "max_replies": max_replies,
                    "candidate_count": len(candidates),
                    "candidates": candidates,
                    "most_recent_mention": most_recent_mention,
                    "skipped": skipped,
                }
            ), 200

        replies: list[dict[str, Any]] = []

        for candidate in candidates:
            if len(replies) >= max_replies:
                break

            message_id = str(candidate.get("message_id", "")).strip()
            if not message_id:
                continue

            author_id = str(candidate.get("user_id", "")).strip()
            if not author_id:
                continue

            if target_message_ids and message_id not in target_message_ids:
                continue

            if not bool(candidate.get("reply_eligible", False)):
                continue

            status = candidate.get("activity_status") if isinstance(candidate.get("activity_status"), dict) else {}
            _post_discord_message_reply(
                channel_id,
                message_id,
                author_id,
                status,
                custom_reply_message=reply_message,
            )
            _mark_mention_replied(message_id)
            replies.append(
                {
                    "message_id": message_id,
                    "user_id": author_id,
                    "activity_status": status,
                    "custom_reply_used": bool(reply_message.strip()),
                }
            )

        return jsonify(
            {
                "status": "ok",
                "mode": "respond",
                "channel_id": channel_id,
                "scan_limit": scan_limit,
                "lookback_limit": lookback_limit,
                "max_replies": max_replies,
                "reply_count": len(replies),
                "targeted_message_count": len(target_message_ids) if target_message_ids else 0,
                "replies": replies,
                "skipped": skipped,
            }
        ), 200

    except ApiError as exc:
        payload: dict[str, Any] = {"error": exc.message}
        guidance = _error_guidance(exc.message)
        if guidance:
            payload.update(guidance)
        if exc.debug:
            payload["debug"] = exc.debug
        if channel_id:
            payload["channel_id"] = channel_id
        return jsonify(payload), exc.status_code


@app.route("/health")
def health() -> tuple[Any, int]:
    """Health endpoint with public load stats and auth-gated detail."""
    oauth_configured = bool(
        DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET and DISCORD_OAUTH_REDIRECT_URI
    )

    endpoint_state: dict[str, Any] = {
        "has_discord_token": bool(DISCORD_TOKEN),
        "has_shared_secret": bool(TP_SHARED_SECRET),
        "oauth_enabled": TP_OAUTH_ENABLED,
        "oauth_configured": oauth_configured,
        "api_keys_enabled": TP_ENABLE_API_KEYS,
    }

    if get_db:
        try:
            endpoint_state.update(get_db().get_sanitized_system_state())
        except Exception:
            endpoint_state["state_counts_unavailable"] = True

    if not endpoint_state["has_discord_token"]:
        setup_stage = "missing_discord_token"
    elif not endpoint_state["oauth_enabled"]:
        setup_stage = "oauth_disabled"
    elif not endpoint_state["oauth_configured"]:
        setup_stage = "oauth_not_configured"
    elif endpoint_state.get("active_api_keys", 0) == 0:
        setup_stage = "ready_no_keys_issued"
    else:
        setup_stage = "ready"
    endpoint_state["setup_stage"] = setup_stage

    payload: dict[str, Any] = {
        "status": "healthy",
        "version": BOT_VERSION,
        "revision": APP_REVISION,
        "build": APP_BUILD,
        "runtime_signature": APP_RUNTIME_SIGNATURE,
        "messages_telemetry": _message_metrics_snapshot(),
        "endpoint_state": endpoint_state,
    }

    # If an API key is supplied, validate it and include tenant + key budget info.
    key_supplied = bool(
        request.headers.get("X-TinyPeople-Key", "").strip()
        or request.args.get("tp_key", "").strip()
    )
    if key_supplied:
        try:
            auth_context = _require_tenant_api_key_context()
        except ApiError as exc:
            return jsonify({"error": exc.message}), exc.status_code

        db = get_db()
        usage = db.get_rate_limit_usage(
            auth_context.key_id,
            window_seconds=TP_RATE_LIMIT_WINDOW_SECONDS,
        )
        remaining = max(0, TP_RATE_LIMIT_PER_MINUTE - usage["requests_in_window"])

        payload.update(
            {
                "auth_mode": "api_key",
                "tenant_id": auth_context.tenant_id,
                "key_id": auth_context.key_id,
                "rate_limit": {
                    "max_requests": TP_RATE_LIMIT_PER_MINUTE,
                    "window_seconds": TP_RATE_LIMIT_WINDOW_SECONDS,
                    "requests_in_window": usage["requests_in_window"],
                    "remaining_requests": remaining,
                    "reset_in_seconds": usage["reset_in_seconds"],
                },
            }
        )
        return jsonify(payload), 200

    # Operator details require legacy auth; without auth, keep health minimal.
    legacy_supplied = bool(
        _resolve_secret_from_request() or _resolve_digest_from_request() or _has_signed_auth_material()
    )
    if legacy_supplied:
        try:
            _authorize_request("0", 1)
        except ApiError as exc:
            return jsonify({"error": exc.message}), exc.status_code

        payload.update(
            {
                "auth_mode": "operator",
                "operator_auth_valid": True,
            }
        )

    return jsonify(payload), 200


@app.route("/messages", methods=["GET"])
def get_messages() -> tuple[Any, int]:
    """Return latest messages for a Discord channel by channel ID.
    
    Accepts channel_id + optional message_id, OR a raw discord_url:
      ?discord_url=https://discord.com/channels/GUILD/CHANNEL/MESSAGE
    When discord_url is provided, guild is validated against tenant ownership.
    """
    start_time = time.time()
    debug_enabled = _debug_requested()
    raw_image_mode = _raw_image_mode_requested()
    embed_mode = _embed_mode_requested()
    _record_message_request()

    auth_context = None
    channel_id = None

    try:
        # Resolve API key / tenant auth context (new)
        auth_context, is_key_based = _resolve_auth_context()

        # Parse discord_url shorthand if provided
        discord_url = request.args.get("discord_url", "").strip()
        if discord_url:
            parsed = _parse_discord_url(discord_url)
            if not parsed:
                raise ApiError("invalid_discord_url", 400)
            url_guild_id, url_channel_id, url_message_id = parsed
            # If using a tenant key, ensure guild matches
            if auth_context and auth_context.tenant_id:
                db = get_db()
                tenant = db.get_tenant_by_guild(url_guild_id)
                if not tenant or tenant["tenant_id"] != auth_context.tenant_id:
                    oauth_url = _build_oauth_install_url()
                    raise ApiError(
                        "guild_not_associated_with_key",
                        403,
                        debug={"guild_id": url_guild_id, "install_url": oauth_url},
                    )
            # Inject extracted params
            channel_id_raw = url_channel_id
            message_id_raw = url_message_id
        else:
            channel_id_raw = request.args.get("channel_id")
            message_id_raw = request.args.get("message_id")

        channel_id = _validate_channel_id(channel_id_raw)
        message_id = _validate_message_id(message_id_raw)
        limit = _parse_limit(request.args.get("limit"))

        # Legacy auth if no API key was used
        if not is_key_based:
            _authorize_request(channel_id, limit)

        # Tenant-scoped channel access
        if auth_context and auth_context.tenant_id and get_db:
            db = get_db()
            if (
                channel_id not in TP_PUBLIC_CHANNEL_IDS
                and not db.is_channel_allowed_for_tenant(auth_context.tenant_id, channel_id)
            ):
                raise ApiError("channel_not_allowed_for_tenant", 403)

        # Per-key rate limit
        if auth_context and auth_context.key_id and get_db:
            db = get_db()
            if not db.check_and_record_rate_limit(
                auth_context.key_id,
                max_requests=TP_RATE_LIMIT_PER_MINUTE,
                window_seconds=TP_RATE_LIMIT_WINDOW_SECONDS,
            ):
                raise ApiError("rate_limit_exceeded", 429)

        # Fetch from Discord
        if message_id:
            messages = [
                _fetch_discord_message_by_id(
                    channel_id,
                    message_id,
                    include_raw_images=raw_image_mode,
                    embed_mode=embed_mode,
                )
            ]
        else:
            messages = _fetch_discord_messages(
                channel_id,
                limit,
                include_raw_images=raw_image_mode,
                embed_mode=embed_mode,
            )

        # Audit log
        if auth_context and get_db:
            latency_ms = int((time.time() - start_time) * 1000)
            get_db().audit_log(
                caller_id=auth_context.caller_id,
                action="fetch_messages",
                status=200,
                latency_ms=latency_ms,
                tenant_id=auth_context.tenant_id,
                key_id=auth_context.key_id,
                channel_id=channel_id,
            )

    except ApiError as exc:
        if auth_context and get_db:
            latency_ms = int((time.time() - start_time) * 1000)
            get_db().audit_log(
                caller_id=auth_context.caller_id,
                action="fetch_messages",
                status=exc.status_code,
                latency_ms=latency_ms,
                tenant_id=auth_context.tenant_id,
                key_id=auth_context.key_id,
                channel_id=channel_id or request.args.get("channel_id", ""),
            )

        payload: dict[str, Any] = {"error": exc.message}
        guidance = _error_guidance(exc.message)
        if guidance:
            payload.update(guidance)

        # Attach install URL for any bot-permission or auth error so
        # agents and users know exactly what action to take next.
        oauth_url = _build_oauth_install_url()
        if oauth_url and exc.status_code in (401, 403, 503):
            payload["install_url"] = oauth_url
            payload["install_hint"] = (
                "Add this bot to your Discord server using the install_url, "
                "then request an API key to access your channels."
            )

        if debug_enabled:
            payload["debug"] = {
                "channel_id": channel_id or request.args.get("channel_id", ""),
                "message_id": request.args.get("message_id", ""),
                "image_mode": request.args.get("tp_image_mode", "")
                or request.args.get("image_mode", ""),
                "embed_mode": request.args.get("tp_embed_mode", "")
                or request.args.get("embed_mode", ""),
                "limit": request.args.get("limit", ""),
                "hint": "For private threads, the bot must be an explicit thread member with Read Message History.",
                "embed_hint": "Use tp_embed_mode=structured to receive a compact embed projection, or omit it for raw Discord embed JSON.",
            }
            if exc.debug:
                payload["debug"].update(exc.debug)
        return jsonify(payload), exc.status_code

    if debug_enabled:
        return (
            jsonify(
                {
                    "messages": messages,
                    "debug": {
                        "channel_id": channel_id,
                        "message_id": message_id,
                        "image_mode": "raw" if raw_image_mode else "off",
                        "embed_mode": embed_mode,
                        "limit": limit,
                        "returned_count": len(messages),
                        "hint": "If returned_count is 0 for a private thread, add the bot as a thread member and grant Read Message History.",
                        "embed_hint": "Use tp_embed_mode=structured for limited agents, or leave it blank for raw embeds.",
                    },
                }
            ),
            200,
        )

    return jsonify(messages), 200


@app.route("/image-chunk", methods=["GET"])
def get_image_chunk() -> tuple[Any, int]:
    """Return a single base64 chunk of an image by URL and chunk index.

    Query params:
      url        - Discord CDN image URL (required)
      chunk      - zero-based chunk index (default 0)
      chunk_chars - chars per chunk (default RAW_IMAGE_CHUNK_CHARS)
      tp_digest / tp_secret / etc - auth as normal
    """
    try:
        _authorize_request("0", 1)
    except ApiError as exc:
        payload: dict[str, Any] = {"error": exc.message}
        guidance = _error_guidance(exc.message)
        if guidance:
            payload.update(guidance)
        return jsonify(payload), exc.status_code

    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "missing_url"}), 400

    try:
        chunk_index = int(request.args.get("chunk", "0"))
    except ValueError:
        return jsonify({"error": "invalid_chunk_index"}), 400

    try:
        chunk_chars = int(request.args.get("chunk_chars", str(RAW_IMAGE_CHUNK_CHARS)))
        chunk_chars = max(1024, min(chunk_chars, 65536))
    except ValueError:
        chunk_chars = RAW_IMAGE_CHUNK_CHARS

    try:
        resp = requests.get(url, timeout=RAW_IMAGE_FETCH_TIMEOUT_SECONDS)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return jsonify({"error": f"fetch_failed:{type(exc).__name__}"}), 502

    body = resp.content
    if len(body) > RAW_IMAGE_MODE_MAX_BYTES:
        return jsonify({
            "error": "image_too_large",
            "size_bytes": len(body),
            "max_bytes": RAW_IMAGE_MODE_MAX_BYTES,
        }), 413

    b64 = base64.b64encode(body).decode("ascii")
    chunks = _chunk_text(b64, chunk_chars)
    total = len(chunks)

    if chunk_index < 0 or chunk_index >= total:
        return jsonify({
            "error": "chunk_index_out_of_range",
            "chunk_count": total,
        }), 400

    return jsonify({
        "url": url,
        "content_type": resp.headers.get("content-type", ""),
        "size_bytes": len(body),
        "encoding": "base64",
        "chunk_chars": chunk_chars,
        "chunk_index": chunk_index,
        "chunk_count": total,
        "chunk": chunks[chunk_index],
    }), 200


@app.route("/oauth/authorize")
def oauth_authorize() -> tuple[Any, int]:
    """Step 1: Redirect user to Discord bot install + authorize page.

    How it works for you (operator) and new users:
    - Visit /oauth/authorize in a browser.
    - Discord shows the "Add to Server" screen for the bot.
    - After approving, Discord redirects to DISCORD_OAUTH_REDIRECT_URI (/oauth/callback).
    - The callback creates a tenant record for the guild, mints an API key, and
      shows it once. That key is what agents use in tp_key= going forward.

    Agent-driven pairing flow (Magic Link):
    - Agent supplies ?pairing_id=RANDOM_TOKEN to get back JSON with an authorize_url
      to hand to the user rather than a redirect.
    - After the user authorizes, the agent calls /oauth/claim?pairing_id=...&tp_digest=...
      to collect the key without the user needing to copy anything.
    """
    if not TP_OAUTH_ENABLED:
        oauth_url = _build_oauth_install_url()
        return jsonify({
            "error": "oauth_not_enabled",
            "hint": "Set TP_OAUTH_ENABLED=1 and configure DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_OAUTH_REDIRECT_URI in .env",
            "install_url": oauth_url,
        }), 503

    if not (DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET and DISCORD_OAUTH_REDIRECT_URI):
        return jsonify({"error": "oauth_not_configured"}), 503

    # Optional agent-driven pairing: caller provides a stable pairing_id they will
    # use later to claim the key via /oauth/claim (no copy-paste needed).
    pairing_id = request.args.get("pairing_id", "").strip() or None
    if pairing_id and (
        len(pairing_id) > 128
        or not re.fullmatch(r"[A-Za-z0-9_\-]+", pairing_id)
    ):
        return jsonify({
            "error": "invalid_pairing_id",
            "hint": "pairing_id must be URL-safe alphanumeric, dash, or underscore — max 128 chars.",
        }), 400

    db = get_db()
    state = secrets.token_urlsafe(32)
    db.store_oauth_state(
        state,
        ttl_seconds=TP_OAUTH_STATE_TTL_SECONDS,
        pairing_id=pairing_id,
    )

    redirect_url = (
        f"https://discord.com/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&permissions={DISCORD_BOT_PERMISSIONS}"
        f"&redirect_uri={DISCORD_OAUTH_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=bot+identify"
        f"&state={state}"
    )

    if pairing_id:
        # Agent-driven pairing: return JSON so the agent can hand the URL to the user.
        return jsonify({
            "status": "pairing_initiated",
            "pairing_id": pairing_id,
            "authorize_url": redirect_url,
            "claim_url": f"{TP_BASE_URL}/oauth/claim?pairing_id={pairing_id}",
            "hint": (
                f"Have the user open authorize_url and approve the bot. "
                f"Then call claim_url to retrieve the key. "
                f"The claim window is {TP_OAUTH_SHOW_ONCE_TTL_SECONDS}s after the user authorizes."
            ),
        }), 200

    from flask import redirect as flask_redirect
    return flask_redirect(redirect_url, 302)


@app.route("/oauth/callback")
def oauth_callback() -> tuple[Any, int]:
    """Step 2: Discord redirects here after user approves bot install.

    Exchanges the code for a token, reads guild + user identity,
    creates or retrieves the tenant record, mints a fresh API key,
    and redirects/returns a show-once token to retrieve it.
    """
    if not TP_OAUTH_ENABLED:
        return jsonify({"error": "oauth_not_enabled"}), 503

    error = request.args.get("error", "").strip()
    if error:
        return jsonify({"error": f"discord_oauth_denied: {error}"}), 403

    code = request.args.get("code", "").strip()
    state = request.args.get("state", "").strip()

    if not code:
        return jsonify({"error": "missing_oauth_code"}), 400

    # Validate CSRF state
    if state:
        db = get_db()
        valid, pairing_id = db.consume_oauth_state(state)
        if not valid:
            return jsonify({"error": "invalid_or_expired_oauth_state"}), 403
    else:
        return jsonify({"error": "missing_oauth_state"}), 400

    # Exchange code for access token
    try:
        token_resp = requests.post(
            "https://discord.com/api/v10/oauth2/token",
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_OAUTH_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
    except requests.RequestException as exc:
        return jsonify({"error": f"discord_token_exchange_failed: {type(exc).__name__}"}), 502

    access_token = token_data.get("access_token", "")
    guild_data = token_data.get("guild", {})  # present when scope includes bot
    guild_id = str(guild_data.get("id", "")).strip() if guild_data else ""

    # Fetch installer identity (scope: identify)
    installer_user = {}
    if access_token:
        try:
            me_resp = requests.get(
                "https://discord.com/api/v10/users/@me",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            if me_resp.status_code == 200:
                installer_user = me_resp.json()
        except requests.RequestException:
            pass  # Non-fatal; guild record is what matters

    if not guild_id:
        return jsonify({
            "error": "no_guild_in_callback",
            "hint": "Ensure the OAuth scope includes 'bot' so Discord includes guild data in the callback.",
        }), 400

    # Create or retrieve tenant, mint API key
    db = get_db()
    tenant = db.create_or_get_tenant(guild_id)
    key_id, raw_key = db.mint_api_key(tenant["tenant_id"])

    # Store show-once token (configurable TTL; agent or browser picks it up)
    show_token = secrets.token_urlsafe(24)
    now = int(time.time())
    _SHOW_ONCE[show_token] = {
        "raw_key": raw_key,
        "key_id": key_id,
        "guild_id": guild_id,
        "installer": installer_user.get("username", "unknown"),
        "tenant_id": tenant["tenant_id"],
        "is_new_tenant": tenant["is_new"],
        "pairing_id": pairing_id,
        "expires_at": now + TP_OAUTH_SHOW_ONCE_TTL_SECONDS,
    }
    if pairing_id:
        _PAIRING_INDEX[pairing_id] = show_token

    return jsonify({
        "status": "authorized",
        "guild_id": guild_id,
        "tenant_id": tenant["tenant_id"],
        "is_new_tenant": tenant["is_new"],
        "installer": installer_user.get("username", "unknown"),
        "key_retrieve_url": f"/oauth/key?token={show_token}",
        "key_retrieve_hint": (
            f"Fetch your API key from key_retrieve_url within {TP_OAUTH_SHOW_ONCE_TTL_SECONDS} seconds. "
            "It is shown once and never stored in plaintext."
        ),
    }), 200


@app.route("/oauth/key")
def oauth_key() -> tuple[Any, int]:
    """Step 3: Retrieve the raw API key once via the show-once token.

    The raw key is stored in memory for a short configurable TTL after OAuth callback.
    After retrieval (or expiry) it is discarded. Store it securely — it
    cannot be recovered, only revoked and re-issued.

    Usage: GET /oauth/key?token=SHOW_ONCE_TOKEN
    """
    token = request.args.get("token", "").strip()
    if not token:
        return jsonify({"error": "missing_token"}), 400

    now = int(time.time())

    # Prune expired entries
    expired = [k for k, v in _SHOW_ONCE.items() if v["expires_at"] <= now]
    for k in expired:
        expired_entry = _SHOW_ONCE.pop(k, None)
        if expired_entry and expired_entry.get("pairing_id"):
            _PAIRING_INDEX.pop(expired_entry["pairing_id"], None)

    entry = _SHOW_ONCE.pop(token, None)
    if not entry:
        return jsonify({
            "error": "show_once_token_invalid_or_expired",
            "hint": f"The key can only be retrieved once within {TP_OAUTH_SHOW_ONCE_TTL_SECONDS}s of OAuth. Re-run /oauth/authorize to get a new key.",
        }), 404

    return jsonify({
        "api_key": entry["raw_key"],
        "key_id": entry["key_id"],
        "tenant_id": entry["tenant_id"],
        "guild_id": entry["guild_id"],
        "installer": entry["installer"],
        "is_new_tenant": entry["is_new_tenant"],
        "usage_hint": (
            "Pass this key as ?tp_key=YOUR_KEY on any /messages request. "
            "Keep it secret. To rotate, re-run /oauth/authorize."
        ),
        "example_url": f"/messages?discord_url=https://discord.com/channels/{entry['guild_id']}/CHANNEL_ID&tp_key={entry['raw_key']}",
    }), 200


@app.route("/oauth/claim")
def oauth_claim() -> tuple[Any, int]:
    """Claim an API key by pairing_id after the user has completed OAuth.

    Part of the agent-driven Magic Link flow:
    1. Agent calls GET /oauth/authorize?pairing_id=RANDOM -> gets authorize_url.
    2. Agent shows the URL to the user; user clicks and authorizes the bot.
    3. Agent calls GET /oauth/claim?pairing_id=RANDOM -> gets the key.

    One-time retrieval — expires at the same
    TTL as the show-once token (TP_OAUTH_SHOW_ONCE_TTL_SECONDS after authorization).

    Returns 202 if the user has not yet authorized (safe to poll).
    Returns 200 with the key on first successful claim.
    Returns 410 if already claimed.
    """
    if not TP_OAUTH_ENABLED:
        return jsonify({"error": "oauth_not_enabled"}), 503

    pairing_id = request.args.get("pairing_id", "").strip()
    if not pairing_id:
        return jsonify({"error": "missing_pairing_id"}), 400

    now = int(time.time())
    # Prune expired show-once entries and their pairing index entries
    expired = [k for k, v in _SHOW_ONCE.items() if v["expires_at"] <= now]
    for k in expired:
        expired_entry = _SHOW_ONCE.pop(k, None)
        if expired_entry and expired_entry.get("pairing_id"):
            _PAIRING_INDEX.pop(expired_entry["pairing_id"], None)

    show_token = _PAIRING_INDEX.get(pairing_id)
    if not show_token:
        # 202: user may not have authorized yet — safe for the agent to poll
        return jsonify({
            "status": "pending_or_expired",
            "error": "pairing_not_ready",
            "hint": "The user has not yet completed authorization, or the claim window has expired.",
            "next_step": (
                f"If the user has not authorized yet, wait and retry. "
                f"Claims expire {TP_OAUTH_SHOW_ONCE_TTL_SECONDS}s after authorization. "
                "To restart, call /oauth/authorize?pairing_id=NEW_ID with a fresh pairing_id."
            ),
        }), 202

    _PAIRING_INDEX.pop(pairing_id, None)
    entry = _SHOW_ONCE.pop(show_token, None)
    if not entry:
        return jsonify({
            "error": "pairing_already_claimed",
            "hint": "This pairing was already claimed or expired.",
        }), 410

    return jsonify({
        "api_key": entry["raw_key"],
        "key_id": entry["key_id"],
        "tenant_id": entry["tenant_id"],
        "guild_id": entry["guild_id"],
        "installer": entry["installer"],
        "is_new_tenant": entry["is_new_tenant"],
        "usage_hint": (
            "Pass this key as ?tp_key=YOUR_KEY on any /messages request. "
            "Keep it secret. To rotate, call /oauth/authorize with a new pairing_id."
        ),
        "example_url": f"/messages?discord_url=https://discord.com/channels/{entry['guild_id']}/CHANNEL_ID&tp_key={entry['raw_key']}",
    }), 200


@app.route("/keys", methods=["GET"])
def list_keys() -> tuple[Any, int]:
    """List keys for the caller's tenant. Requires a tenant API key."""
    try:
        auth_context = _require_tenant_api_key_context()
    except ApiError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    include_revoked = request.args.get("include_revoked", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    db = get_db()
    keys = db.list_api_keys_for_tenant(
        auth_context.tenant_id,
        include_revoked=include_revoked,
    )
    active_count = db.count_active_api_keys(auth_context.tenant_id)

    return jsonify(
        {
            "tenant_id": auth_context.tenant_id,
            "active_key_count": active_count,
            "keys": keys,
        }
    ), 200


@app.route("/keys/issue", methods=["GET"])
def issue_key() -> tuple[Any, int]:
    """Issue a new API key for the caller's tenant. Requires a tenant API key."""
    try:
        auth_context = _require_tenant_api_key_context()
    except ApiError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    db = get_db()
    key_id, raw_key = db.mint_api_key(auth_context.tenant_id)

    db.audit_log(
        caller_id=auth_context.caller_id,
        action="issue_key",
        status=200,
        latency_ms=0,
        tenant_id=auth_context.tenant_id,
        key_id=auth_context.key_id,
    )

    return jsonify(
        {
            "status": "issued",
            "tenant_id": auth_context.tenant_id,
            "key_id": key_id,
            "api_key": raw_key,
            "warning": "Store this key now. Raw keys are never recoverable from the server.",
        }
    ), 200


@app.route("/keys/revoke", methods=["GET"])
def revoke_key() -> tuple[Any, int]:
    """Revoke a tenant API key by key_id. Requires a tenant API key."""
    try:
        auth_context = _require_tenant_api_key_context()
    except ApiError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    target_key_id = request.args.get("key_id", "").strip()
    if not target_key_id:
        return jsonify({"error": "missing_key_id"}), 400

    db = get_db()
    keys = db.list_api_keys_for_tenant(auth_context.tenant_id, include_revoked=True)
    target = next((item for item in keys if item["key_id"] == target_key_id), None)
    if not target:
        return jsonify({"error": "key_not_found"}), 404

    if target.get("revoked_at") is not None:
        return jsonify({"status": "already_revoked", "key_id": target_key_id}), 200

    active_count = db.count_active_api_keys(auth_context.tenant_id)
    if target_key_id == auth_context.key_id and active_count <= 1:
        return (
            jsonify(
                {
                    "error": "cannot_revoke_last_active_key",
                    "hint": "Issue a replacement key first via /keys/issue.",
                }
            ),
            409,
        )

    revoked = db.revoke_api_key(auth_context.tenant_id, target_key_id)
    if not revoked:
        return jsonify({"error": "key_not_active"}), 409

    db.audit_log(
        caller_id=auth_context.caller_id,
        action="revoke_key",
        status=200,
        latency_ms=0,
        tenant_id=auth_context.tenant_id,
        key_id=auth_context.key_id,
    )

    return jsonify(
        {
            "status": "revoked",
            "key_id": target_key_id,
            "active_key_count": db.count_active_api_keys(auth_context.tenant_id),
        }
    ), 200


@app.route("/channels/list", methods=["GET"])
def list_channels() -> tuple[Any, int]:
    """List tenant channel grants and globally public channels."""
    try:
        auth_context = _require_tenant_api_key_context()
    except ApiError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    db = get_db()
    grants = db.list_channel_grants_for_tenant(auth_context.tenant_id)
    public_ids = sorted(TP_PUBLIC_CHANNEL_IDS)

    return jsonify(
        {
            "tenant_id": auth_context.tenant_id,
            "public_channel_ids": public_ids,
            "grants": grants,
            "grant_count": len(grants),
            "effective_channel_count": len({item["channel_id"] for item in grants}.union(public_ids)),
        }
    ), 200


@app.route("/channels/grant", methods=["GET"])
def grant_channel() -> tuple[Any, int]:
    """Grant a channel to the caller's tenant allowlist. Requires tenant API key."""
    try:
        auth_context = _require_tenant_api_key_context()
    except ApiError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    channel_id_raw = request.args.get("channel_id")
    try:
        channel_id = _validate_channel_id(channel_id_raw)
    except ApiError as exc:
        payload = {"error": exc.message}
        guidance = _error_guidance(exc.message)
        if guidance:
            payload.update(guidance)
        return jsonify(payload), exc.status_code

    db = get_db()
    already_allowed = (
        channel_id in TP_PUBLIC_CHANNEL_IDS
        or db.is_channel_allowed_for_tenant(auth_context.tenant_id, channel_id)
    )

    if channel_id not in TP_PUBLIC_CHANNEL_IDS:
        db.add_channel_grant(auth_context.tenant_id, channel_id)

    db.audit_log(
        caller_id=auth_context.caller_id,
        action="grant_channel",
        status=200,
        latency_ms=0,
        tenant_id=auth_context.tenant_id,
        key_id=auth_context.key_id,
        channel_id=channel_id,
    )

    return jsonify(
        {
            "status": "already_allowed" if already_allowed else "granted",
            "tenant_id": auth_context.tenant_id,
            "channel_id": channel_id,
            "is_public_channel": channel_id in TP_PUBLIC_CHANNEL_IDS,
            "hint": "Use this channel_id with /messages via channel_id=... or discord_url=...",
        }
    ), 200


@app.route("/channels/revoke", methods=["GET"])
def revoke_channel() -> tuple[Any, int]:
    """Revoke a channel grant from caller tenant. Public channels are not revocable here."""
    try:
        auth_context = _require_tenant_api_key_context()
    except ApiError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    channel_id_raw = request.args.get("channel_id")
    try:
        channel_id = _validate_channel_id(channel_id_raw)
    except ApiError as exc:
        payload = {"error": exc.message}
        guidance = _error_guidance(exc.message)
        if guidance:
            payload.update(guidance)
        return jsonify(payload), exc.status_code

    if channel_id in TP_PUBLIC_CHANNEL_IDS:
        return jsonify(
            {
                "error": "channel_is_globally_public",
                "hint": "This channel is allowed via TP_PUBLIC_CHANNEL_IDS and is not tenant-scoped.",
            }
        ), 409

    db = get_db()
    removed = db.remove_channel_grant(auth_context.tenant_id, channel_id)

    db.audit_log(
        caller_id=auth_context.caller_id,
        action="revoke_channel",
        status=200 if removed else 404,
        latency_ms=0,
        tenant_id=auth_context.tenant_id,
        key_id=auth_context.key_id,
        channel_id=channel_id,
    )

    if not removed:
        return jsonify({"status": "not_found", "channel_id": channel_id}), 404

    return jsonify(
        {
            "status": "revoked",
            "tenant_id": auth_context.tenant_id,
            "channel_id": channel_id,
        }
    ), 200


@app.route("/terms")
def terms() -> tuple[Any, int]:
    """Terms of Service — required by Discord for public OAuth applications."""
    TP_SERVICE_NAME = os.getenv("TP_SERVICE_NAME", "tinyPeople Discord Messages API")
    TP_CONTACT_EMAIL = os.getenv("TP_CONTACT_EMAIL", "")
    TP_BASE_URL = os.getenv("TP_BASE_URL", "https://your-domain")
    body = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Terms of Service — {TP_SERVICE_NAME}</title>
<style>body{{font-family:sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;line-height:1.6}}
h1{{font-size:1.5rem}}h2{{font-size:1.1rem;margin-top:2rem}}a{{color:#5865F2}}</style>
</head>
<body>
<h1>Terms of Service</h1>
<p><strong>{TP_SERVICE_NAME}</strong></p>
<p>Last updated: April 2026</p>

<h2>1. Service Description</h2>
<p>This service provides an API that reads messages from Discord channels your bot account
has been authorised to access. It does not send messages, modify servers, or store message content.</p>

<h2>2. Authorisation</h2>
<p>By installing this bot to your Discord server via the OAuth flow, you authorise it to read
messages in channels it has been granted access to. You can remove the bot from your server at
any time via Discord server settings.</p>

<h2>3. API Keys</h2>
<p>Each API key is scoped to the guild that authorised it. Keys are stored as one-way hashes;
the raw key is shown once at creation and cannot be recovered. Keep your key secret.
Do not share keys across users. Re-issue via <a href="{TP_BASE_URL}/oauth/authorize">/oauth/authorize</a> if compromised.</p>

<h2>4. Rate Limits</h2>
<p>Requests are rate-limited per API key to protect both the Discord API and other users of
this service. Repeated limit violations may result in key suspension.</p>

<h2>5. No Warranty</h2>
<p>This service is provided as-is. No guarantee of uptime, accuracy, or fitness for a particular
purpose is made.</p>

<h2>6. Changes</h2>
<p>These terms may be updated. Continued use after changes constitutes acceptance.</p>

{"<h2>7. Contact</h2><p>Questions: <a href='mailto:" + TP_CONTACT_EMAIL + "'>" + TP_CONTACT_EMAIL + "</a></p>" if TP_CONTACT_EMAIL else ""}
</body>
</html>"""
    return Response(body, mimetype="text/html"), 200


@app.route("/privacy")
def privacy() -> tuple[Any, int]:
    """Privacy Policy — required by Discord for public OAuth applications."""
    TP_SERVICE_NAME = os.getenv("TP_SERVICE_NAME", "tinyPeople Discord Messages API")
    TP_CONTACT_EMAIL = os.getenv("TP_CONTACT_EMAIL", "")
    body = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Privacy Policy — {TP_SERVICE_NAME}</title>
<style>body{{font-family:sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;line-height:1.6}}
h1{{font-size:1.5rem}}h2{{font-size:1.1rem;margin-top:2rem}}</style>
</head>
<body>
<h1>Privacy Policy</h1>
<p><strong>{TP_SERVICE_NAME}</strong></p>
<p>Last updated: September 2026</p>

<h2>What we collect</h2>
<ul>
  <li><strong>Guild ID</strong>: stored to associate your server with your API key.</li>
  <li><strong>Installer username</strong>: stored once at OAuth time for audit purposes.</li>
  <li><strong>Request metadata</strong>: timestamp, channel ID, HTTP status, latency — stored
      in an audit log. No message content is stored.</li>
  <li><strong>API key hash</strong>: SHA-256 hash of your key. The raw key is never stored.</li>
</ul>

<h2>What we do not collect</h2>
<ul>
  <li>We do not store Discord message content, except the source-message context and proposed reply held in a pending affirm-reply proposal until it is approved, expires (1 hour), or is deleted.</li>
  <li>We do not store user IDs of people who send messages, except the requesting agent/key and, transiently, the source author identifier within a pending reply proposal.</li>
  <li>We do not sell or share data with third parties.</li>
</ul>

<h2>Discord API</h2>
<p>Message data is fetched live from Discord's API using a bot token on your behalf.
Discord's own <a href="https://discord.com/privacy">Privacy Policy</a> applies to that data.</p>

<h2>Data retention</h2>
<p>Audit log entries and tenant records persist until manually purged by the operator.
You can request deletion by revoking your bot from your server and contacting the operator.</p>

{"<h2>Contact</h2><p>" + TP_CONTACT_EMAIL + "</p>" if TP_CONTACT_EMAIL else ""}
</body>
</html>"""
    return Response(body, mimetype="text/html"), 200




# REPLY_PROPOSAL_WORKFLOW_APP_V2
def _reply_authenticate_channel(channel_id):
    auth_context = _require_tenant_api_key_context()
    db = get_db()
    if (
        channel_id not in TP_PUBLIC_CHANNEL_IDS
        and not db.is_channel_allowed_for_tenant(auth_context.tenant_id, channel_id)
    ):
        raise ApiError("channel_not_allowed_for_tenant", 403)
    return auth_context, db

def _reply_response(response, status=None):
    if not hasattr(response, "headers"):
        response = Response(response, mimetype="text/html")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Robots-Tag"] = "noindex"
    if status is not None:
        response.status_code = status
    return response

def _reply_error_response(exc):
    body = f"<p><strong>Error:</strong> {html.escape(str(exc), quote=True)}</p>"
    return _reply_response(Response(body, mimetype="text/html"), getattr(exc, "status_code", 500))

def _reply_render(proposal, notice=""):
    if not proposal:
        return _reply_response(Response("<p>Reply proposal not found.</p>", mimetype="text/html"), 404)
    try:
        context = json.loads(proposal.get("source_context") or "{}")
    except (TypeError, ValueError):
        context = {}
    esc = lambda value: html.escape(str(value or ""), quote=True)
    proposal_id = esc(proposal.get("proposal_id"))
    status = esc(proposal.get("status"))
    source_id = esc(proposal.get("source_message_id"))
    author = esc(context.get("author_name") or context.get("username") or "unknown")
    content = esc(context.get("content"))
    reply = esc(proposal.get("reply_message"))
    href_id = quote(str(proposal.get("proposal_id") or ""), safe="")
    base = request.url_root.rstrip("/")
    approve_url = html.escape(
        f"{base}/discord/replies/approve?proposal_id={href_id}", quote=True
    )
    confirm_url = html.escape(approve_url + "&confirm=1", quote=True)
    notice_html = f"<p><strong>{esc(notice)}</strong></p>" if notice else ""
    body = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Reply proposal</title></head>
<body>
<h1>Discord reply proposal</h1>
{notice_html}
<p><strong>Status:</strong> {status}</p>
<p><strong>Proposal:</strong> {proposal_id}</p>
<p><strong>Source message:</strong> {source_id}</p>
<p><strong>Author:</strong> {author}</p>
<p><strong>Source:</strong></p><pre>{content}</pre>
<p><strong>Reply:</strong></p><pre>{reply}</pre>
<p><a href="{approve_url}">Review only</a> or
<a href="{confirm_url}">Confirm and send</a>.</p>
</body></html>"""
    return _reply_response(Response(body, mimetype="text/html"))

def _reply_source_context(source):
    author = source.get("author") if isinstance(source.get("author"), dict) else {}
    return json.dumps(
        {
            "author_name": str(author.get("global_name") or author.get("display_name") or author.get("username") or "unknown"),
            "username": str(author.get("username") or ""),
            "author_id": str(author.get("id") or source.get("author_id") or ""),
            "content": str(source.get("content") or "")[:500],
            "timestamp": str(source.get("timestamp") or ""),
        },
        separators=(",", ":"),
    )

@app.route("/discord/replies/propose", methods=["GET"])
def discord_replies_propose():
    try:
        channel_id = _validate_channel_id(request.args.get("channel_id"))
        source_message_id = _validate_message_id(
            request.args.get("message_id") or request.args.get("source_message_id")
        )
        reply_message = request.args.get("reply_message", "")
        if not reply_message.strip():
            raise ApiError("missing_reply_message", 400)
        auth_context, db = _reply_authenticate_channel(channel_id)
        source = _fetch_discord_message_by_id(channel_id, source_message_id)
        history = _fetch_discord_messages_raw(channel_id, min(100, max(1, MENTION_REPLY_LOOKBACK_LIMIT)))
        bot_user_id = _fetch_discord_bot_user_id()
        if _bot_already_replied_to_message(
            mention_message_id=source_message_id,
            bot_user_id=bot_user_id,
            channel_history=history,
        ):
            return _reply_response(
                Response("<p>Already replied to this message.</p>", mimetype="text/html"), 409
            )
        now = int(time.time())
        proposal = db.create_reply_proposal(
            proposal_id=secrets.token_urlsafe(32),
            tenant_id=auth_context.tenant_id,
            channel_id=channel_id,
            source_message_id=source_message_id,
            reply_message=reply_message,
            source_context=_reply_source_context(source),
            created_at=now,
            expires_at=now + 3600,
        )
        return _reply_render(proposal, "No message was sent. A human must confirm explicitly.")
    except ApiError as exc:
        return _reply_error_response(exc)

@app.route("/discord/replies/approve", methods=["GET"])
def discord_replies_approve():
    proposal_id = request.args.get("proposal_id", "").strip()
    if not proposal_id:
        return _reply_response(Response("<p>Missing proposal_id.</p>", mimetype="text/html"), 400)
    try:
        db = get_db()
        proposal = db.get_reply_proposal(proposal_id)
        if not proposal:
            return _reply_response(Response("<p>Reply proposal not found.</p>", mimetype="text/html"), 404)
        _auth_context, db = _reply_authenticate_channel(proposal["channel_id"])
        now = int(time.time())
        db.expire_reply_proposal_if_needed(proposal_id, now)
        proposal = db.get_reply_proposal(proposal_id)
        confirm = request.args.get("confirm", "").strip().lower() in {"1", "true", "yes", "on"}
        if not confirm:
            return _reply_render(proposal, "Review only. Nothing will be sent without confirm=1.")
        if proposal.get("status") != "pending":
            return _reply_render(proposal, "This proposal is not pending and was not sent.")
        if not db.claim_reply_proposal(proposal_id, now):
            return _reply_render(db.get_reply_proposal(proposal_id), "Another request claimed this proposal, or it expired.")
        proposal = db.get_reply_proposal(proposal_id)
        channel_id = proposal["channel_id"]
        source_message_id = proposal["source_message_id"]
        history = _fetch_discord_messages_raw(channel_id, min(100, max(1, MENTION_REPLY_LOOKBACK_LIMIT)))
        bot_user_id = _fetch_discord_bot_user_id()
        # Re-check Discord after the atomic claim and immediately before send.
        if _bot_already_replied_to_message(
            mention_message_id=source_message_id,
            bot_user_id=bot_user_id,
            channel_history=history,
        ):
            db.mark_reply_proposal_sent(proposal_id, "already_replied")
            return _reply_render(db.get_reply_proposal(proposal_id), "Already replied; no duplicate was sent.")
        try:
            _post_discord_message_reply(
                channel_id,
                source_message_id,
                str(proposal.get("source_context") or ""),
                {},
                custom_reply_message=proposal["reply_message"],
            )
        except Exception as exc:
            db.restore_reply_proposal_pending(proposal_id, str(exc))
            return _reply_render(db.get_reply_proposal(proposal_id), f"Send failed; proposal restored: {exc}")
        db.mark_reply_proposal_sent(proposal_id, "sent")
        return _reply_render(db.get_reply_proposal(proposal_id), "Reply sent exactly once.")
    except ApiError as exc:
        return _reply_error_response(exc)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), debug=False)
