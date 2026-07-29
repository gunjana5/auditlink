# uses create_app + tmp_path so we don't touch the real db

from __future__ import annotations

from datetime import timedelta
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import to_iso, utc_now
from app.main import create_app
from app.security import (
    hash_passphrase,
    resolve_under_storage,
    sanitize_display_name,
    verify_passphrase,
)


@pytest.fixture
def client(tmp_path: Path):
    storage = tmp_path / "storage"
    storage.mkdir()
    app = create_app(
        storage_dir=storage,
        db_path=tmp_path / "test.db",
        audit_token="",  # open audit for most tests
        rate_limit_max=1000,
    )
    with TestClient(app) as c:
        yield c


def _upload(
    client: TestClient,
    content: bytes = b"hello auditlink",
    filename: str = "notes.txt",
    passphrase: str = "",
    expiry_hours: int = 24,
    max_downloads: int = 3,
):
    # helper - always ask for json so we get the token back cleanly
    return client.post(
        "/upload",
        files={"file": (filename, BytesIO(content), "text/plain")},
        data={
            "passphrase": passphrase,
            "expiry_hours": str(expiry_hours),
            "max_downloads": str(max_downloads),
        },
        headers={"Accept": "application/json"},
    )


def test_upload_then_download(client: TestClient):
    up = _upload(client, content=b"secret payload")
    assert up.status_code == 200
    body = up.json()
    token = body["token"]
    assert body["requires_passphrase"] is False

    page = client.get(f"/d/{token}")
    assert page.status_code == 200
    assert "notes.txt" in page.text

    dl = client.post(f"/d/{token}")
    assert dl.status_code == 200
    assert dl.content == b"secret payload"

    audit = client.get("/api/audit").json()["events"]
    types = [e["event_type"] for e in audit]
    assert "upload" in types
    assert "download_success" in types


def test_passphrase_required(client: TestClient):
    token = _upload(client, passphrase="correct-horse").json()["token"]

    bad = client.post(f"/d/{token}", data={"passphrase": "wrong"})
    assert bad.status_code == 403

    ok = client.post(f"/d/{token}", data={"passphrase": "correct-horse"})
    assert ok.status_code == 200
    assert ok.content == b"hello auditlink"

    denied = [
        e
        for e in client.get("/api/audit").json()["events"]
        if e["event_type"] == "download_denied"
    ]
    assert any(e["detail"] == "bad_passphrase" for e in denied)


def test_expired_share_denied(client: TestClient, tmp_path: Path):
    # Build app with access to db for backdating
    storage = tmp_path / "storage2"
    storage.mkdir()
    app = create_app(storage_dir=storage, db_path=tmp_path / "exp.db", audit_token="")
    with TestClient(app) as c:
        token = _upload(c).json()["token"]
        # cheat the clock - shove expires_at into the past
        past = to_iso(utc_now() - timedelta(hours=1))
        with app.state.db.connect() as conn:
            conn.execute(
                "UPDATE shares SET expires_at = ? WHERE token = ?",
                (past, token),
            )
        resp = c.post(f"/d/{token}")
        assert resp.status_code == 410
        events = c.get("/api/audit").json()["events"]
        assert any(e["event_type"] == "expired" for e in events)
        assert any(
            e["event_type"] == "download_denied" and e["detail"] == "expired"
            for e in events
        )


def test_max_downloads(client: TestClient):
    token = _upload(client, max_downloads=1).json()["token"]
    assert client.post(f"/d/{token}").status_code == 200
    second = client.post(f"/d/{token}")
    assert second.status_code == 410
    events = client.get("/api/audit").json()["events"]
    assert any(
        e["event_type"] == "download_denied" and e["detail"] == "max_downloads_reached"
        for e in events
    )


def test_file_stored_with_random_name(client: TestClient):
    # on-disk name must not match the upload name
    token = _upload(client, filename="report.pdf").json()["token"]
    share = client.app.state.db.get_share(token)
    assert share is not None
    assert share.original_filename == "report.pdf"
    assert share.stored_name != "report.pdf"
    assert ".." not in share.stored_name
    path = resolve_under_storage(client.app.state.storage, share.stored_name)
    assert path.is_file()


def test_path_traversal_sanitized():
    assert sanitize_display_name("../../etc/passwd") == "passwd"
    assert sanitize_display_name("safe_file-1.txt") == "safe_file-1.txt"


def test_resolve_rejects_traversal(tmp_path: Path):
    with pytest.raises(ValueError):
        resolve_under_storage(tmp_path, "../escape.bin")
    with pytest.raises(ValueError):
        resolve_under_storage(tmp_path, "subdir/file.bin")


def test_passphrase_hash_roundtrip():
    salt, digest = hash_passphrase("s3cret")
    assert verify_passphrase("s3cret", salt, digest)
    assert not verify_passphrase("nope", salt, digest)


def test_audit_token_protection(tmp_path: Path):
    # when AUDIT_TOKEN is set the endpoint should 401 without it
    app = create_app(
        storage_dir=tmp_path / "s",
        db_path=tmp_path / "a.db",
        audit_token="super-secret",
    )
    with TestClient(app) as c:
        assert c.get("/api/audit").status_code == 401
        ok = c.get("/api/audit", headers={"X-Audit-Token": "super-secret"})
        assert ok.status_code == 200
        assert "events" in ok.json()


def test_rate_limit_logs_event(tmp_path: Path):
    app = create_app(
        storage_dir=tmp_path / "s",
        db_path=tmp_path / "r.db",
        rate_limit_max=2,
    )
    with TestClient(app) as c:
        token = _upload(c, max_downloads=10).json()["token"]
        assert c.post(f"/d/{token}").status_code == 200
        assert c.post(f"/d/{token}").status_code == 200
        limited = c.post(f"/d/{token}")
        assert limited.status_code == 429
        events = c.get("/api/audit").json()["events"]
        assert any(e["event_type"] == "rate_limited" for e in events)


def test_home_renders(client: TestClient):
    r = client.get("/")
    assert r.status_code == 200
    assert "auditlink" in r.text
    assert "Generate link" in r.text
