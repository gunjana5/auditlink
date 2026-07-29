# Share.is_expired / downloads_exhausted live here so routes stay thin

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

# sqlite - simple, no server to run for a portfolio demo
SCHEMA = """
CREATE TABLE IF NOT EXISTS shares (
    token TEXT PRIMARY KEY,
    original_filename TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    content_type TEXT,
    size_bytes INTEGER NOT NULL,
    passphrase_salt TEXT,
    passphrase_hash TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_downloads INTEGER NOT NULL,
    download_count INTEGER NOT NULL DEFAULT 0,
    content_sha256 TEXT,
    manage_token TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    token TEXT,
    ip TEXT,
    detail TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
"""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    # always store utc iso strings - easier than dealing with naive datetimes later
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(value: str) -> datetime:
    # fromisoformat handles the +00:00 we write out
    return datetime.fromisoformat(value)


@dataclass
class Share:
    token: str
    original_filename: str
    stored_name: str
    content_type: Optional[str]
    size_bytes: int
    passphrase_salt: Optional[str]
    passphrase_hash: Optional[str]
    created_at: str
    expires_at: str
    max_downloads: int
    download_count: int
    content_sha256: Optional[str] = None
    manage_token: Optional[str] = None
    revoked_at: Optional[str] = None

    @property
    def requires_passphrase(self) -> bool:
        # hash present = uploader set a passphrase
        return bool(self.passphrase_hash)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        # now injectable so tests can freeze time without sleeping
        now = now or utc_now()
        return parse_iso(self.expires_at) <= now

    def downloads_exhausted(self) -> bool:
        return self.download_count >= self.max_downloads

    def is_revoked(self) -> bool:
        return bool(self.revoked_at)

    def status_label(self, now: Optional[datetime] = None) -> str:
        if self.is_revoked():
            return "revoked"
        if self.is_expired(now):
            return "expired"
        if self.downloads_exhausted():
            return "exhausted"
        return "live"


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        # parent may be a tmp_path in tests
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        # check_same_thread=False - fastapi can hit us from different workers in tests
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate_shares(conn)
            # after migrate so old dbs have the column first
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_manage
                ON shares(manage_token)
                WHERE manage_token IS NOT NULL
                """
            )

    def _migrate_shares(self, conn: sqlite3.Connection) -> None:
        # old dbs created before content_sha256 / manage_token / revoked_at
        cols = {row[1] for row in conn.execute("PRAGMA table_info(shares)").fetchall()}
        for name, typ in (
            ("content_sha256", "TEXT"),
            ("manage_token", "TEXT"),
            ("revoked_at", "TEXT"),
        ):
            if name not in cols:
                conn.execute(f"ALTER TABLE shares ADD COLUMN {name} {typ}")

    def create_share(
        self,
        *,
        token: str,
        original_filename: str,
        stored_name: str,
        content_type: Optional[str],
        size_bytes: int,
        passphrase_salt: Optional[str],
        passphrase_hash: Optional[str],
        expires_at: datetime,
        max_downloads: int,
        content_sha256: str,
        manage_token: str,
    ) -> Share:
        created = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO shares (
                    token, original_filename, stored_name, content_type, size_bytes,
                    passphrase_salt, passphrase_hash, created_at, expires_at,
                    max_downloads, download_count, content_sha256, manage_token, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL)
                """,
                (
                    token,
                    original_filename,
                    stored_name,
                    content_type,
                    size_bytes,
                    passphrase_salt,
                    passphrase_hash,
                    to_iso(created),
                    to_iso(expires_at),
                    max_downloads,
                    content_sha256,
                    manage_token,
                ),
            )
        # re-read so callers get a full Share dataclass
        return self.get_share(token)  # type: ignore[return-value]

    def _row_to_share(self, row: sqlite3.Row) -> Share:
        data = dict(row)
        # tolerate older rows missing new keys
        data.setdefault("content_sha256", None)
        data.setdefault("manage_token", None)
        data.setdefault("revoked_at", None)
        return Share(**data)

    def get_share(self, token: str) -> Optional[Share]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM shares WHERE token = ?", (token,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_share(row)

    def get_share_by_manage_token(self, manage_token: str) -> Optional[Share]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM shares WHERE manage_token = ?", (manage_token,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_share(row)

    def revoke_share(self, token: str, now: Optional[datetime] = None) -> None:
        when = to_iso(now or utc_now())
        with self.connect() as conn:
            conn.execute(
                "UPDATE shares SET revoked_at = ? WHERE token = ? AND revoked_at IS NULL",
                (when, token),
            )

    def list_cleanup_candidates(self, now: Optional[datetime] = None) -> list[Share]:
        # expired or revoked - blobs can go; row stays for audit join
        now_iso = to_iso(now or utc_now())
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM shares
                WHERE revoked_at IS NOT NULL
                   OR expires_at <= ?
                """,
                (now_iso,),
            ).fetchall()
        return [self._row_to_share(r) for r in rows]

    def clear_stored_name(self, token: str) -> None:
        # mark blob gone without wiping the share row
        with self.connect() as conn:
            conn.execute(
                "UPDATE shares SET stored_name = '' WHERE token = ?",
                (token,),
            )

    def increment_download(self, token: str) -> None:
        # called just before FileResponse - count wins even if client aborts mid-stream
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE shares
                SET download_count = download_count + 1
                WHERE token = ?
                """,
                (token,),
            )

    def log_event(
        self,
        event_type: str,
        *,
        token: Optional[str] = None,
        ip: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        # append-only - we never update / delete audit rows
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (event_type, token, ip, detail, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_type, token, ip, detail, to_iso(utc_now())),
            )

    def recent_audit(
        self,
        limit: int = 100,
        *,
        event_type: Optional[str] = None,
        token_prefix: Optional[str] = None,
    ) -> list[dict]:
        # newest first for the api / ops desk
        clauses: list[str] = []
        params: list[object] = []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if token_prefix:
            clauses.append("token LIKE ?")
            params.append(f"{token_prefix}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id, event_type, token, ip, detail, created_at
                FROM audit_log
                {where}
                ORDER BY id DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    def audit_counts(self) -> dict[str, int]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT event_type, COUNT(*) AS n
                FROM audit_log
                GROUP BY event_type
                """
            ).fetchall()
        return {str(r["event_type"]): int(r["n"]) for r in rows}
