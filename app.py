#!/usr/bin/env python3
"""tinyPeople Discord Messages API.

Provides a shared-secret-protected endpoint that fetches latest messages
from a Discord channel using a bot token that stays server-side.
"""

from __future__ import annotations

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

BOT_VERSION = "0.1.0"
APP_DIR = os.path.dirname(__file__)
load_dotenv(os.path.join(APP_DIR, ".env"))
load_dotenv(os.path.join(APP_DIR, ".deploy-stamp.env"))

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
DEFAULT_MESSAGE_LIMIT = int(os.getenv("DEFAULT_MESSAGE_LIMIT", "20"))
MAX_MESSAGE_LIMIT = int(os.getenv("MAX_MESSAGE_LIMIT", "50"))
DISCORD_HTTP_TIMEOUT_SECONDS = float(os.getenv("DISCORD_HTTP_TIMEOUT_SECONDS", "15"))

ALLOWED_CHANNEL_IDS = {
    channel_id.strip()
    for channel_id in os.getenv("ALLOWED_CHANNEL_IDS", "").split(",")
    if channel_id.strip()
}

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


def _debug_requested() -> bool:
    """Return True when debug output is explicitly requested and allowed."""
    if not ALLOW_DEBUG_QUERY_PARAM:
        return False

    raw = request.args.get("tp_debug", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


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


def _format_author(author: dict[str, Any]) -> str:
    """Normalize Discord author object into stable display name."""
    username = author.get("username", "unknown")
    discriminator = author.get("discriminator", "")
    if discriminator and discriminator != "0":
        return f"{username}#{discriminator}"
    return username


def _normalize_message(message: dict[str, Any]) -> dict[str, Any]:
    """Convert Discord message payload to contract output shape."""
    content = message.get("content", "")

    # Preserve signal for non-text entries while keeping the response compact.
    if not content and message.get("attachments"):
        content = "[attachment]"

    return {
        "timestamp": message.get("timestamp"),
        "author": _format_author(message.get("author", {})),
        "content": content,
    }


def _fetch_discord_messages(channel_id: str, limit: int) -> list[dict[str, Any]]:
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

    return [_normalize_message(msg) for msg in data]


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
    debug_enabled = _debug_requested()
    _record_message_request()
    try:
        channel_id = _validate_channel_id(request.args.get("channel_id"))
        limit = _parse_limit(request.args.get("limit"))
        _authorize_request(channel_id, limit)
        messages = _fetch_discord_messages(channel_id, limit)
    except ApiError as exc:
        payload: dict[str, Any] = {"error": exc.message}
        if debug_enabled:
            payload["debug"] = {
                "channel_id": request.args.get("channel_id", ""),
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
                        "limit": limit,
                        "returned_count": len(messages),
                        "hint": "If returned_count is 0 for a private thread, add the bot as a thread member and grant Read Message History.",
                    },
                }
            ),
            200,
        )

    return jsonify(messages), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), debug=False)
