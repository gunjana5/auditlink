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
    download_count INTEGER NOT NULL DEFAULT 0
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

    @property
    def requires_passphrase(self) -> bool:
        return bool(self.passphrase_hash)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        now = now or utc_now()
        return parse_iso(self.expires_at) <= now

    def downloads_exhausted(self) -> bool:
        return self.download_count >= self.max_downloads


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
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
    ) -> Share:
        created = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO shares (
                    token, original_filename, stored_name, content_type, size_bytes,
                    passphrase_salt, passphrase_hash, created_at, expires_at,
                    max_downloads, download_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
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
                ),
            )
        return self.get_share(token)  # type: ignore[return-value]

    def get_share(self, token: str) -> Optional[Share]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM shares WHERE token = ?", (token,)
            ).fetchone()
        if row is None:
            return None
        return Share(**dict(row))

    def increment_download(self, token: str) -> None:
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

    def recent_audit(self, limit: int = 100) -> list[dict]:
        # newest first for the api
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, event_type, token, ip, detail, created_at
                FROM audit_log
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
