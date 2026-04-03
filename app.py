#!/usr/bin/env python3
"""tinyPeople Discord Messages API.

Provides a shared-secret-protected endpoint that fetches latest messages
from a Discord channel using a bot token that stays server-side.
"""

from __future__ import annotations

import hmac
import os
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
DEFAULT_MESSAGE_LIMIT = int(os.getenv("DEFAULT_MESSAGE_LIMIT", "20"))
MAX_MESSAGE_LIMIT = int(os.getenv("MAX_MESSAGE_LIMIT", "50"))
DISCORD_HTTP_TIMEOUT_SECONDS = float(os.getenv("DISCORD_HTTP_TIMEOUT_SECONDS", "15"))

ALLOWED_CHANNEL_IDS = {
    channel_id.strip()
    for channel_id in os.getenv("ALLOWED_CHANNEL_IDS", "").split(",")
    if channel_id.strip()
}

app = Flask(__name__)


@dataclass
class ApiError(Exception):
    """Simple structured API error."""

    message: str
    status_code: int


def _resolve_secret_from_request() -> str:
    """Get shared secret from supported headers."""
    explicit_secret = request.headers.get("X-TinyPeople-Secret", "").strip()
    if explicit_secret:
        return explicit_secret

    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    return ""


def _authorize_request() -> None:
    """Validate shared secret without exposing sensitive values."""
    if not TP_SHARED_SECRET:
        raise ApiError("server_missing_shared_secret", 503)

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
        raise ApiError("discord_upstream_unreachable", 502) from exc

    if response.status_code == 401:
        raise ApiError("discord_token_rejected", 502)
    if response.status_code == 403:
        raise ApiError("discord_forbidden_channel", 403)
    if response.status_code == 404:
        raise ApiError("discord_channel_not_found", 404)
    if response.status_code >= 400:
        raise ApiError("discord_upstream_error", 502)

    data = response.json()
    if not isinstance(data, list):
        raise ApiError("discord_unexpected_payload", 502)

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
            }
        ),
        200,
    )


@app.route("/messages", methods=["GET"])
def get_messages() -> tuple[Any, int]:
    """Return latest messages for a Discord channel by channel ID."""
    try:
        _authorize_request()
        channel_id = _validate_channel_id(request.args.get("channel_id"))
        limit = _parse_limit(request.args.get("limit"))
        messages = _fetch_discord_messages(channel_id, limit)
    except ApiError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    return jsonify(messages), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), debug=False)
