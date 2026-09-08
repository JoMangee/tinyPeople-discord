"""SQLite-backed identity, key, and tenant store for tinyPeople API.

Provides lightweight multi-tenant isolation:
- Tenants: Discord guilds that have authenticated via OAuth.
- API Keys: Per-tenant issued keys for external access (raw key never stored).
- Channel Grants: Per-tenant channel allowlist.
- Rate Limits: Per-key rolling window counters.
- OAuth States: Short-lived CSRF state tokens for the OAuth install flow.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
import time
import uuid
from threading import Lock
from typing import Any, NamedTuple

__version__ = "0.3.2"


class AuthContext(NamedTuple):
    """Caller identity from auth resolution."""

    caller_id: str  # tenant_id:key_id or "shared_secret" or "digest"
    tenant_id: str | None  # Discord guild ID if tenant-scoped; None for demo/shared auth
    key_id: str | None  # API key ID if key-based; None for shared/digest
    auth_mode: str  # "shared_secret", "digest", "signed", "api_key"


class Database:
    """SQLite conn pool and schema management."""

    def __init__(self, db_path: str | None = None):
        """Initialize database."""
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), "var", "tinypeople.db"
            )
        self.db_path = db_path
        self._local = threading.local()
        self._lock = Lock()
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            self._local.conn = sqlite3.connect(
                self.db_path,
                timeout=5.0,
                check_same_thread=False,
            )
            # Enable WAL mode for concurrent reads under Passenger workers
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
        return self._local.conn

    def _init_schema(self) -> None:
        """Create tables on startup if missing (idempotent)."""
        conn = self._get_conn()
        cursor = conn.cursor()

        try:
            # Tenants (Discord guilds that have authorized)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    guild_id TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )

            # API Keys (per-tenant)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
                )
                """
            )

            # Channel Grants (per-tenant channel allowlist)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS channel_grants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE(tenant_id, channel_id),
                    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
                )
                """
            )

            # Rate Limit Counters (per-key, rolling window)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS rate_limit_buckets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT NOT NULL,
                    window_start INTEGER NOT NULL,
                    request_count INTEGER NOT NULL DEFAULT 1,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(key_id, window_start),
                    FOREIGN KEY (key_id) REFERENCES api_keys(key_id)
                )
                """
            )

            # Audit Log (request metadata for observability)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    tenant_id TEXT,
                    key_id TEXT,
                    caller_id TEXT NOT NULL,
                    channel_id TEXT,
                    action TEXT NOT NULL,
                    status INTEGER,
                    latency_ms INTEGER
                )
                """
            )

            # OAuth States (short-lived CSRF tokens for install flow)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_states (
                    state TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    pairing_id TEXT
                )
                """
            )
            # Migration: add pairing_id column to existing DBs that lack it
            try:
                cursor.execute("ALTER TABLE oauth_states ADD COLUMN pairing_id TEXT")
            except sqlite3.OperationalError:
                pass  # Column already exists

            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            raise RuntimeError(f"Failed to initialize schema: {e}") from e

    def close(self) -> None:
        """Close thread-local connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def get_api_key_by_raw(self, raw_key: str) -> dict[str, Any] | None:
        """Look up API key by the raw key value (compared via hash).
        
        Raw key is never stored; only sha256 hash is kept.
        """
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT key_id, tenant_id, created_at, revoked_at
            FROM api_keys
            WHERE key_hash = ? AND revoked_at IS NULL
            """,
            (key_hash,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "key_id": row[0],
            "tenant_id": row[1],
            "created_at": row[2],
            "revoked_at": row[3],
        }

    def get_api_key(self, key_id: str) -> dict[str, Any] | None:
        """Look up API key by internal key_id."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT key_id, tenant_id, created_at, revoked_at
            FROM api_keys
            WHERE key_id = ? AND revoked_at IS NULL
            """,
            (key_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "key_id": row[0],
            "tenant_id": row[1],
            "created_at": row[2],
            "revoked_at": row[3],
        }

    def is_channel_allowed_for_tenant(
        self, tenant_id: str, channel_id: str
    ) -> bool:
        """Check if channel is on tenant's allowlist."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT 1 FROM channel_grants
            WHERE tenant_id = ? AND channel_id = ?
            """,
            (tenant_id, channel_id),
        )
        return cursor.fetchone() is not None

    def check_and_record_rate_limit(
        self,
        key_id: str,
        max_requests: int,
        window_seconds: int,
    ) -> bool:
        """Check if key is within rate limit and record request.
        
        Returns True if request is allowed; False if limit exceeded.
        """
        now = int(time.time())
        window_start = now - window_seconds

        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            # Count requests in current window
            cursor.execute(
                """
                SELECT SUM(request_count) FROM rate_limit_buckets
                WHERE key_id = ? AND window_start >= ?
                """,
                (key_id, window_start),
            )
            row = cursor.fetchone()
            current_count = row[0] if row and row[0] else 0

            if current_count >= max_requests:
                return False

            # Record this request
            cursor.execute(
                """
                INSERT INTO rate_limit_buckets (key_id, window_start, request_count, updated_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(key_id, window_start) DO UPDATE SET request_count = request_count + 1
                """,
                (key_id, window_start, now),
            )
            conn.commit()
            return True

    def get_rate_limit_usage(self, key_id: str, window_seconds: int) -> dict[str, int]:
        """Return request usage for a key in the active rolling window."""
        now = int(time.time())
        cutoff = now - window_seconds
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COALESCE(SUM(request_count), 0), MIN(window_start)
            FROM rate_limit_buckets
            WHERE key_id = ? AND window_start >= ?
            """,
            (key_id, cutoff),
        )
        row = cursor.fetchone()
        requests_in_window = int(row[0]) if row and row[0] is not None else 0
        oldest_window_start = int(row[1]) if row and row[1] is not None else 0

        reset_in_seconds = 0
        if oldest_window_start > 0:
            reset_in_seconds = max(0, window_seconds - (now - oldest_window_start))

        return {
            "requests_in_window": requests_in_window,
            "window_seconds": window_seconds,
            "reset_in_seconds": reset_in_seconds,
        }

    def audit_log(
        self,
        caller_id: str,
        action: str,
        status: int,
        latency_ms: int = 0,
        tenant_id: str | None = None,
        key_id: str | None = None,
        channel_id: str | None = None,
    ) -> None:
        """Record request metadata for observability."""
        now = int(time.time())
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_log
            (timestamp, tenant_id, key_id, caller_id, channel_id, action, status, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now, tenant_id, key_id, caller_id, channel_id, action, status, latency_ms),
        )
        conn.commit()


    def create_or_get_tenant(self, guild_id: str) -> dict[str, Any]:
        """Create a tenant record for a guild, or return existing one."""
        now = int(time.time())
        conn = self._get_conn()
        cursor = conn.cursor()
        # Try to get existing
        cursor.execute(
            "SELECT tenant_id, guild_id, created_at FROM tenants WHERE guild_id = ?",
            (guild_id,),
        )
        row = cursor.fetchone()
        if row:
            return {"tenant_id": row[0], "guild_id": row[1], "created_at": row[2], "is_new": False}
        # Create new
        tenant_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO tenants (tenant_id, guild_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (tenant_id, guild_id, now, now),
        )
        conn.commit()
        return {"tenant_id": tenant_id, "guild_id": guild_id, "created_at": now, "is_new": True}

    def mint_api_key(self, tenant_id: str, label: str = "") -> tuple[str, str]:
        """Create a new API key for a tenant.
        
        Returns (key_id, raw_key). The raw_key is only returned here and never
        stored — only its sha256 hash is persisted. Show it to the user once.
        """
        now = int(time.time())
        raw_key = "tp_" + secrets.token_urlsafe(32)
        key_id = str(uuid.uuid4())
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO api_keys (key_id, tenant_id, key_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (key_id, tenant_id, key_hash, now, now),
        )
        conn.commit()
        return key_id, raw_key

    def list_api_keys_for_tenant(
        self,
        tenant_id: str,
        include_revoked: bool = False,
    ) -> list[dict[str, Any]]:
        """List API keys for a tenant, optionally including revoked keys."""
        conn = self._get_conn()
        cursor = conn.cursor()
        if include_revoked:
            cursor.execute(
                """
                SELECT key_id, tenant_id, created_at, updated_at, revoked_at
                FROM api_keys
                WHERE tenant_id = ?
                ORDER BY created_at DESC
                """,
                (tenant_id,),
            )
        else:
            cursor.execute(
                """
                SELECT key_id, tenant_id, created_at, updated_at, revoked_at
                FROM api_keys
                WHERE tenant_id = ? AND revoked_at IS NULL
                ORDER BY created_at DESC
                """,
                (tenant_id,),
            )

        rows = cursor.fetchall()
        return [
            {
                "key_id": row[0],
                "tenant_id": row[1],
                "created_at": row[2],
                "updated_at": row[3],
                "revoked_at": row[4],
            }
            for row in rows
        ]

    def count_active_api_keys(self, tenant_id: str) -> int:
        """Return number of active (non-revoked) keys for a tenant."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM api_keys
            WHERE tenant_id = ? AND revoked_at IS NULL
            """,
            (tenant_id,),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    def revoke_api_key(self, tenant_id: str, key_id: str) -> bool:
        """Revoke a tenant key. Returns True if a live key was revoked."""
        now = int(time.time())
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE api_keys
            SET revoked_at = ?, updated_at = ?
            WHERE tenant_id = ? AND key_id = ? AND revoked_at IS NULL
            """,
            (now, now, tenant_id, key_id),
        )
        conn.commit()
        return cursor.rowcount > 0

    def add_channel_grant(self, tenant_id: str, channel_id: str) -> None:
        """Add a channel to a tenant's allowlist (idempotent)."""
        now = int(time.time())
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR IGNORE INTO channel_grants (tenant_id, channel_id, created_at)
            VALUES (?, ?, ?)
            """,
            (tenant_id, channel_id, now),
        )
        conn.commit()

    def list_channel_grants_for_tenant(self, tenant_id: str) -> list[dict[str, Any]]:
        """List channel allowlist entries for a tenant."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT channel_id, created_at
            FROM channel_grants
            WHERE tenant_id = ?
            ORDER BY created_at DESC
            """,
            (tenant_id,),
        )
        rows = cursor.fetchall()
        return [
            {
                "channel_id": row[0],
                "created_at": row[1],
            }
            for row in rows
        ]

    def remove_channel_grant(self, tenant_id: str, channel_id: str) -> bool:
        """Remove a channel from tenant allowlist. Returns True if removed."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            DELETE FROM channel_grants
            WHERE tenant_id = ? AND channel_id = ?
            """,
            (tenant_id, channel_id),
        )
        conn.commit()
        return cursor.rowcount > 0

    def get_tenant_by_guild(self, guild_id: str) -> dict[str, Any] | None:
        """Look up tenant by Discord guild ID."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT tenant_id, guild_id, created_at FROM tenants WHERE guild_id = ?",
            (guild_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {"tenant_id": row[0], "guild_id": row[1], "created_at": row[2]}

    def store_oauth_state(
        self, state: str, ttl_seconds: int = 300, pairing_id: str | None = None
    ) -> None:
        """Persist a short-lived OAuth CSRF state token."""
        now = int(time.time())
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO oauth_states (state, created_at, expires_at, pairing_id) VALUES (?, ?, ?, ?)",
            (state, now, now + ttl_seconds, pairing_id),
        )
        conn.commit()

    def consume_oauth_state(self, state: str) -> tuple[bool, str | None]:
        """Validate and delete an OAuth state token. Returns (valid, pairing_id)."""
        now = int(time.time())
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT state, pairing_id FROM oauth_states WHERE state = ? AND expires_at > ?",
            (state, now),
        )
        row = cursor.fetchone()
        if not row:
            return False, None
        pairing_id = row[1] if len(row) > 1 else None
        cursor.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
        conn.commit()
        return True, pairing_id

    def get_sanitized_system_state(self) -> dict[str, int]:
        """Return aggregate, non-identifying counts for health reporting."""
        now = int(time.time())
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM tenants")
        tenants_count = int(cursor.fetchone()[0])

        cursor.execute("SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL")
        active_api_keys_count = int(cursor.fetchone()[0])

        cursor.execute("SELECT COUNT(*) FROM channel_grants")
        channel_grants_count = int(cursor.fetchone()[0])

        cursor.execute("SELECT COUNT(*) FROM oauth_states WHERE expires_at > ?", (now,))
        pending_oauth_states_count = int(cursor.fetchone()[0])

        return {
            "authorized_tenants": tenants_count,
            "active_api_keys": active_api_keys_count,
            "channel_grants": channel_grants_count,
            "pending_oauth_states": pending_oauth_states_count,
        }


# Global instance
_db = None


def init_db(db_path: str | None = None) -> Database:
    """Initialize or reinitialize the global DB instance."""
    global _db
    _db = Database(db_path)
    return _db


def get_db() -> Database:
    """Get global DB instance (must call init_db first)."""
    global _db
    if _db is None:
        _db = Database()
    return _db


# REPLY_PROPOSAL_WORKFLOW_DB_V2
def _reply_proposal_row(row):
    if not row:
        return None
    columns = (
        "proposal_id", "tenant_id", "channel_id", "source_message_id",
        "reply_message", "source_context", "status", "created_at",
        "expires_at", "approved_at", "sent_at", "result", "error",
    )
    return dict(zip(columns, row))

def _reply_init_schema(self):
    _reply_original_init_schema(self)
    conn = self._get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reply_proposals (
            proposal_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            source_message_id TEXT NOT NULL,
            reply_message TEXT NOT NULL,
            source_context TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending','approved','sent','expired','failed')),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            approved_at INTEGER,
            sent_at INTEGER,
            result TEXT,
            error TEXT,
            UNIQUE(channel_id, source_message_id)
        )
        """
    )
    conn.commit()

def create_reply_proposal(
    self, proposal_id, tenant_id, channel_id, source_message_id,
    reply_message, source_context, created_at, expires_at
):
    conn = self._get_conn()
    conn.execute(
        """
        INSERT OR IGNORE INTO reply_proposals
        (proposal_id, tenant_id, channel_id, source_message_id,
         reply_message, source_context, status, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
        (proposal_id, tenant_id, channel_id, source_message_id,
         reply_message, source_context, created_at, expires_at),
    )
    conn.commit()
    return (
        self.get_reply_proposal(proposal_id)
        or self.get_reply_proposal_by_source(channel_id, source_message_id)
    )

def get_reply_proposal(self, proposal_id):
    row = self._get_conn().execute(
        """
        SELECT proposal_id, tenant_id, channel_id, source_message_id,
               reply_message, source_context, status, created_at,
               expires_at, approved_at, sent_at, result, error
        FROM reply_proposals WHERE proposal_id = ?
        """,
        (proposal_id,),
    ).fetchone()
    return _reply_proposal_row(row)

def get_reply_proposal_by_source(self, channel_id, source_message_id):
    row = self._get_conn().execute(
        """
        SELECT proposal_id, tenant_id, channel_id, source_message_id,
               reply_message, source_context, status, created_at,
               expires_at, approved_at, sent_at, result, error
        FROM reply_proposals
        WHERE channel_id = ? AND source_message_id = ?
        """,
        (channel_id, source_message_id),
    ).fetchone()
    return _reply_proposal_row(row)

def expire_reply_proposal_if_needed(self, proposal_id, now):
    conn = self._get_conn()
    cur = conn.execute(
        """
        UPDATE reply_proposals
        SET status = 'expired', error = COALESCE(error, 'expired')
        WHERE proposal_id = ? AND status = 'pending' AND expires_at <= ?
        """,
        (proposal_id, now),
    )
    conn.commit()
    return cur.rowcount > 0

def claim_reply_proposal(self, proposal_id, now):
    conn = self._get_conn()
    cur = conn.execute(
        """
        UPDATE reply_proposals
        SET status = 'approved', approved_at = ?, error = NULL
        WHERE proposal_id = ? AND status = 'pending' AND expires_at > ?
        """,
        (now, proposal_id, now),
    )
    conn.commit()
    return cur.rowcount > 0

def mark_reply_proposal_sent(self, proposal_id, result="sent"):
    conn = self._get_conn()
    cur = conn.execute(
        """
        UPDATE reply_proposals
        SET status = 'sent', sent_at = ?, result = ?, error = NULL
        WHERE proposal_id = ? AND status = 'approved'
        """,
        (int(time.time()), result, proposal_id),
    )
    conn.commit()
    return cur.rowcount > 0

def restore_reply_proposal_pending(self, proposal_id, error=""):
    conn = self._get_conn()
    cur = conn.execute(
        """
        UPDATE reply_proposals
        SET status = 'pending', approved_at = NULL, error = ?
        WHERE proposal_id = ? AND status = 'approved'
        """,
        (error, proposal_id),
    )
    conn.commit()
    return cur.rowcount > 0

_reply_original_init_schema = Database._init_schema
Database._init_schema = _reply_init_schema
Database.create_reply_proposal = create_reply_proposal
Database.get_reply_proposal = get_reply_proposal
Database.get_reply_proposal_by_source = get_reply_proposal_by_source
Database.expire_reply_proposal_if_needed = expire_reply_proposal_if_needed
Database.claim_reply_proposal = claim_reply_proposal
Database.mark_reply_proposal_sent = mark_reply_proposal_sent
Database.restore_reply_proposal_pending = restore_reply_proposal_pending
