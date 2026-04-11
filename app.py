#!/usr/bin/env python3
"""tinyPeople Discord Messages API.

Provides a shared-secret-protected endpoint that fetches latest messages
from a Discord channel using a bot token that stays server-side.
"""

from __future__ import annotations

import base64
from collections import deque
import hmac
import hashlib
import os
from threading import Lock
import time
from dataclasses import dataclass
from typing import Any

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request

try:
    from db import get_db, init_db, AuthContext
except ImportError:
    # db module optional; can run without multi-tenant features
    get_db = None
    init_db = None
    AuthContext = None

BOT_VERSION = "0.2.0"
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

ALLOWED_CHANNEL_IDS = {
    channel_id.strip()
    for channel_id in os.getenv("ALLOWED_CHANNEL_IDS", "").split(",")
    if channel_id.strip()
}

# Multi-tenant rate limiting and API keys (Phase 1)
TP_RATE_LIMIT_PER_MINUTE = int(os.getenv("TP_RATE_LIMIT_PER_MINUTE", "30"))
TP_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("TP_RATE_LIMIT_WINDOW_SECONDS", "60"))
TP_ENABLE_API_KEYS = (
    os.getenv("TP_ENABLE_API_KEYS", "0").strip().lower()
    in {"1", "true", "yes", "on"}
)

app = Flask(__name__)
RECENT_NONCES: dict[str, int] = {}
MESSAGE_REQUEST_TIMESTAMPS: deque[int] = deque()
MESSAGE_HOST_SEEN_AT: dict[str, int] = {}
MESSAGE_METRICS_LOCK = Lock()


@dataclass
class ApiError(Exception):
    """Simple structured API error."""

    message: str
    status_code: int
    debug: dict[str, Any] | None = None


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

    # API key provided; validate it
    db = get_db()
    key_info = db.get_api_key(api_key)
    if not key_info:
        raise ApiError("invalid_api_key", 403)
    
    context = AuthContext(
        caller_id=api_key,
        tenant_id=key_info["tenant_id"],
        key_id=api_key,
        auth_mode="api_key",
    )
    return context, True


def _debug_requested() -> bool:
    """Return True when debug output is explicitly requested and allowed."""
    if not ALLOW_DEBUG_QUERY_PARAM:
        return False

    raw = request.args.get("tp_debug", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _raw_image_mode_requested() -> bool:
    """Return True when caller asks for raw image payloads."""
    mode = request.args.get("tp_image_mode", "").strip().lower()
    if mode == "raw":
        return True

    mode = request.args.get("image_mode", "").strip().lower()
    return mode == "raw"


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

    if not hmac.compare_digest(provided.lower(), expected):
        raise ApiError("invalid_digest", 403)


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


def _normalize_message(
    message: dict[str, Any], *, include_raw_images: bool = False
) -> dict[str, Any]:
    """Convert Discord message payload to contract output shape."""
    content = message.get("content", "")
    raw_attachments = message.get("attachments")
    attachments = raw_attachments if isinstance(raw_attachments, list) else []
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

    # Preserve signal for non-text entries while keeping the response compact.
    if not content and attachments:
        content = "[attachment]"

    normalized = {
        "timestamp": message.get("timestamp"),
        "message_id": message.get("id"),
        "author": _format_author(message.get("author", {})),
        "content": content,
        "attachment_urls": attachment_urls,
        "image_urls": image_urls,
    }

    if include_raw_images:
        normalized["raw_images"] = _build_raw_image_payloads(attachments)

    return normalized


def _fetch_discord_message_by_id(
    channel_id: str, message_id: str, *, include_raw_images: bool = False
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

    return _normalize_message(response_body_json, include_raw_images=include_raw_images)


def _fetch_discord_messages(
    channel_id: str, limit: int, *, include_raw_images: bool = False
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

    return [_normalize_message(msg, include_raw_images=include_raw_images) for msg in data]


@app.route("/")
def home() -> tuple[Any, int]:
    """Operator-facing status endpoint."""
    return (
        jsonify(
            {
                "service": "tinyPeople Discord Messages API",
                "status": "alive",
                "version": BOT_VERSION,
                "revision": APP_REVISION,
                "build": APP_BUILD,
                "runtime_signature": APP_RUNTIME_SIGNATURE,
            }
        ),
        200,
    )


@app.route("/health")
def health() -> tuple[Any, int]:
    """Health endpoint for host checks."""
    return (
        jsonify(
            {
                "status": "healthy",
                "version": BOT_VERSION,
                "revision": APP_REVISION,
                "build": APP_BUILD,
                "runtime_signature": APP_RUNTIME_SIGNATURE,
                "has_discord_token": bool(DISCORD_TOKEN),
                "has_shared_secret": bool(TP_SHARED_SECRET),
                "messages_telemetry": _message_metrics_snapshot(),
            }
        ),
        200,
    )


@app.route("/messages", methods=["GET"])
def get_messages() -> tuple[Any, int]:
    """Return latest messages for a Discord channel by channel ID."""
    start_time = time.time()
    debug_enabled = _debug_requested()
    raw_image_mode = _raw_image_mode_requested()
    _record_message_request()
    
    auth_context = None
    channel_id = None
    
    try:
        # Try to resolve API key / tenant auth context (new)
        auth_context, is_key_based = _resolve_auth_context()
        
        # Parse and validate parameters
        channel_id = _validate_channel_id(request.args.get("channel_id"))
        message_id = _validate_message_id(request.args.get("message_id"))
        limit = _parse_limit(request.args.get("limit"))
        
        # If no API key, fall through to legacy shared-secret auth
        if not is_key_based:
            _authorize_request(channel_id, limit)
        
        # Check tenant-scoped channel access if applicable
        if auth_context and auth_context.tenant_id and get_db:
            db = get_db()
            if not db.is_channel_allowed_for_tenant(auth_context.tenant_id, channel_id):
                raise ApiError("channel_not_allowed_for_tenant", 403)
        
        # Check rate limit if using API key
        if auth_context and auth_context.key_id and get_db:
            db = get_db()
            if not db.check_and_record_rate_limit(
                auth_context.key_id,
                max_requests=TP_RATE_LIMIT_PER_MINUTE,
                window_seconds=TP_RATE_LIMIT_WINDOW_SECONDS,
            ):
                raise ApiError("rate_limit_exceeded", 429)
        
        # Fetch messages
        if message_id:
            messages = [
                _fetch_discord_message_by_id(
                    channel_id, message_id, include_raw_images=raw_image_mode
                )
            ]
        else:
            messages = _fetch_discord_messages(
                channel_id, limit, include_raw_images=raw_image_mode
            )
        
        # Log successful request (audit)
        if auth_context and get_db:
            latency_ms = int((time.time() - start_time) * 1000)
            db = get_db()
            db.audit_log(
                caller_id=auth_context.caller_id,
                action="fetch_messages",
                status=200,
                latency_ms=latency_ms,
                tenant_id=auth_context.tenant_id,
                key_id=auth_context.key_id,
                channel_id=channel_id,
            )
        
    except ApiError as exc:
        # Log error (audit)
        if auth_context and get_db:
            latency_ms = int((time.time() - start_time) * 1000)
            db = get_db()
            db.audit_log(
                caller_id=auth_context.caller_id,
                action="fetch_messages",
                status=exc.status_code,
                latency_ms=latency_ms,
                tenant_id=auth_context.tenant_id,
                key_id=auth_context.key_id,
                channel_id=channel_id or request.args.get("channel_id", ""),
            )
        
        payload: dict[str, Any] = {"error": exc.message}
        if debug_enabled:
            payload["debug"] = {
                "channel_id": request.args.get("channel_id", ""),
                "message_id": request.args.get("message_id", ""),
                "image_mode": request.args.get("tp_image_mode", "")
                or request.args.get("image_mode", ""),
                "limit": request.args.get("limit", ""),
                "hint": "For private threads, the bot must be an explicit thread member with Read Message History.",
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
                        "limit": limit,
                        "returned_count": len(messages),
                        "hint": "If returned_count is 0 for a private thread, add the bot as a thread member and grant Read Message History.",
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
        return jsonify({"error": exc.message}), exc.status_code

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), debug=False)
