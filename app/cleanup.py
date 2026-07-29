# drop blobs for expired / revoked / exhausted shares - audit rows stay

from __future__ import annotations

from pathlib import Path

from app.db import Database
from app.security import resolve_under_storage


def cleanup_expired(storage: Path, db: Database) -> int:
    """Delete on-disk blobs for expired, revoked, or exhausted shares. Returns how many removed."""
    removed = 0
    for share in db.list_cleanup_candidates():
        if not share.stored_name:
            continue
        try:
            path = resolve_under_storage(storage, share.stored_name)
        except ValueError:
            db.clear_stored_name(share.token)
            continue
        if path.is_file():
            path.unlink(missing_ok=True)
            removed += 1
            db.log_event(
                "cleanup",
                token=share.token,
                detail=f"removed={share.stored_name}",
            )
        db.clear_stored_name(share.token)
    return removed
