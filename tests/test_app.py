# uses create_app + tmp_path so we don't touch the real db

from __future__ import annotations

import hashlib
from datetime import timedelta
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.cleanup import cleanup_expired
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
    # fresh storage + db per test so nothing leaks between cases
    storage = tmp_path / "storage"
    storage.mkdir()
    app = create_app(
        storage_dir=storage,
        db_path=tmp_path / "test.db",
        audit_token="",  # open audit for most tests
        rate_limit_max=1000,
        run_cleanup_on_start=False,
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
    # happy path: upload -> page -> download -> audit events
    up = _upload(client, content=b"secret payload")
    assert up.status_code == 200
    body = up.json()
    token = body["token"]
    assert body["requires_passphrase"] is False
    assert body["content_sha256"] == hashlib.sha256(b"secret payload").hexdigest()
    assert body["manage_token"]
    assert "/m/" in body["manage_url"]

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

    # wrong guess first - should 403 and leave a denied event
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
    # build app with access to db for backdating
    storage = tmp_path / "storage2"
    storage.mkdir()
    app = create_app(
        storage_dir=storage,
        db_path=tmp_path / "exp.db",
        audit_token="",
        run_cleanup_on_start=False,
    )
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
    # budget of 1 - second hit should 410
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
    # display name keeps the basename only
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
        run_cleanup_on_start=False,
    )
    with TestClient(app) as c:
        assert c.get("/api/audit").status_code == 401
        ok = c.get("/api/audit", headers={"X-Audit-Token": "super-secret"})
        assert ok.status_code == 200
        assert "events" in ok.json()


def test_rate_limit_logs_event(tmp_path: Path):
    # tiny window so the third download attempt trips 429
    app = create_app(
        storage_dir=tmp_path / "s",
        db_path=tmp_path / "r.db",
        rate_limit_max=2,
        run_cleanup_on_start=False,
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


def test_hash_mismatch_denies(client: TestClient):
    body = _upload(client, content=b"clean bytes").json()
    token = body["token"]
    share = client.app.state.db.get_share(token)
    assert share is not None
    path = resolve_under_storage(client.app.state.storage, share.stored_name)
    path.write_bytes(b"tampered")

    resp = client.post(f"/d/{token}")
    assert resp.status_code == 409
    events = client.get("/api/audit").json()["events"]
    assert any(e["event_type"] == "hash_mismatch" for e in events)
    assert any(
        e["event_type"] == "download_denied" and e["detail"] == "hash_mismatch"
        for e in events
    )


def test_manage_revoke(client: TestClient):
    body = _upload(client, content=b"revoke me").json()
    token = body["token"]
    manage = body["manage_token"]

    page = client.get(f"/m/{manage}")
    assert page.status_code == 200
    assert "Manage share" in page.text

    revoked = client.post(
        f"/m/{manage}/revoke",
        headers={"Accept": "application/json"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    share = client.app.state.db.get_share(token)
    assert share is not None
    assert share.is_revoked()
    assert share.stored_name == ""

    dl = client.post(f"/d/{token}")
    assert dl.status_code == 410
    events = client.get("/api/audit").json()["events"]
    assert any(e["event_type"] == "revoked" for e in events)


def test_ops_desk_open_when_no_token(client: TestClient):
    _upload(client)
    page = client.get("/ops")
    assert page.status_code == 200
    assert "Ops desk" in page.text
    assert "demo only" in page.text.lower() or "Demo only" in page.text


def test_ops_requires_token_when_set(tmp_path: Path):
    app = create_app(
        storage_dir=tmp_path / "s",
        db_path=tmp_path / "ops.db",
        audit_token="desk-secret",
        run_cleanup_on_start=False,
    )
    with TestClient(app) as c:
        locked = c.get("/ops")
        assert locked.status_code == 200
        assert "Unlock" in locked.text

        assert c.get("/api/audit").status_code == 401
        assert c.post("/ops/cleanup").status_code == 401

        unlock = c.post("/ops/unlock", data={"key": "desk-secret"}, follow_redirects=False)
        assert unlock.status_code == 303

        desk = c.get("/ops")
        assert desk.status_code == 200
        assert "Unlock" not in desk.text
        assert "Cleanup blobs" in desk.text


def test_cleanup_removes_expired_blob(client: TestClient):
    body = _upload(client, content=b"soon gone").json()
    token = body["token"]
    share = client.app.state.db.get_share(token)
    assert share is not None
    path = resolve_under_storage(client.app.state.storage, share.stored_name)
    assert path.is_file()

    past = to_iso(utc_now() - timedelta(hours=1))
    with client.app.state.db.connect() as conn:
        conn.execute(
            "UPDATE shares SET expires_at = ? WHERE token = ?",
            (past, token),
        )

    removed = cleanup_expired(client.app.state.storage, client.app.state.db)
    assert removed == 1
    assert not path.exists()
    refreshed = client.app.state.db.get_share(token)
    assert refreshed is not None
    assert refreshed.stored_name == ""
    events = client.get("/api/audit").json()["events"]
    assert any(e["event_type"] == "cleanup" for e in events)


def test_security_headers_present(client: TestClient):
    r = client.get("/")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers


def test_upload_oversize_returns_413(tmp_path: Path):
    storage = tmp_path / "s"
    storage.mkdir()
    app = create_app(
        storage_dir=storage,
        db_path=tmp_path / "big.db",
        audit_token="",
        max_upload_bytes=32,
        run_cleanup_on_start=False,
    )
    with TestClient(app) as c:
        resp = c.post(
            "/upload",
            files={"file": ("big.txt", BytesIO(b"x" * 64), "text/plain")},
            data={"passphrase": "", "expiry_hours": "24", "max_downloads": "3"},
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 413


def test_form_clamps_reject_bad_expiry_and_max(client: TestClient):
    bad_expiry = client.post(
        "/upload",
        files={"file": ("a.txt", BytesIO(b"hi"), "text/plain")},
        data={"passphrase": "", "expiry_hours": "0", "max_downloads": "3"},
        headers={"Accept": "application/json"},
    )
    assert bad_expiry.status_code == 400

    bad_max = client.post(
        "/upload",
        files={"file": ("a.txt", BytesIO(b"hi"), "text/plain")},
        data={"passphrase": "", "expiry_hours": "24", "max_downloads": "101"},
        headers={"Accept": "application/json"},
    )
    assert bad_max.status_code == 400


def test_concurrent_max_downloads_cannot_overshoot(tmp_path: Path):
    import threading

    storage = tmp_path / "s"
    storage.mkdir()
    app = create_app(
        storage_dir=storage,
        db_path=tmp_path / "race.db",
        audit_token="",
        rate_limit_max=1000,
        run_cleanup_on_start=False,
    )
    with TestClient(app) as c:
        token = _upload(c, max_downloads=1).json()["token"]
        results: list[bool] = []
        lock = threading.Lock()

        def hit() -> None:
            ok = app.state.db.try_increment_download(token)
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=hit) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count(True) == 1
        assert results.count(False) == 7
        share = app.state.db.get_share(token)
        assert share is not None
        assert share.download_count == 1

        # download path should now see exhausted
        assert c.post(f"/d/{token}").status_code == 410


def test_audit_bearer_auth(tmp_path: Path):
    app = create_app(
        storage_dir=tmp_path / "s",
        db_path=tmp_path / "bearer.db",
        audit_token="super-secret",
        run_cleanup_on_start=False,
    )
    with TestClient(app) as c:
        assert c.get("/api/audit").status_code == 401
        ok = c.get(
            "/api/audit",
            headers={"Authorization": "Bearer super-secret"},
        )
        assert ok.status_code == 200
        assert "events" in ok.json()


def test_ops_cleanup_when_unlocked(tmp_path: Path):
    storage = tmp_path / "s"
    storage.mkdir()
    app = create_app(
        storage_dir=storage,
        db_path=tmp_path / "cleanup.db",
        audit_token="desk-secret",
        run_cleanup_on_start=False,
    )
    with TestClient(app) as c:
        body = _upload(c, content=b"soon gone").json()
        token = body["token"]
        share = app.state.db.get_share(token)
        assert share is not None
        path = resolve_under_storage(storage, share.stored_name)
        assert path.is_file()

        past = to_iso(utc_now() - timedelta(hours=1))
        with app.state.db.connect() as conn:
            conn.execute(
                "UPDATE shares SET expires_at = ? WHERE token = ?",
                (past, token),
            )

        unlock = c.post(
            "/ops/unlock", data={"key": "desk-secret"}, follow_redirects=False
        )
        assert unlock.status_code == 303

        cleaned = c.post(
            "/ops/cleanup",
            headers={"Accept": "application/json"},
        )
        assert cleaned.status_code == 200
        assert cleaned.json()["removed"] == 1
        assert not path.exists()


def test_prod_env_requires_audit_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUDITLINK_ENV", "prod")
    with pytest.raises(RuntimeError, match="AUDIT_TOKEN"):
        create_app(
            storage_dir=tmp_path / "s",
            db_path=tmp_path / "prod.db",
            audit_token="",
            run_cleanup_on_start=False,
        )


def test_query_key_does_not_unlock(tmp_path: Path):
    app = create_app(
        storage_dir=tmp_path / "s",
        db_path=tmp_path / "key.db",
        audit_token="desk-secret",
        run_cleanup_on_start=False,
    )
    with TestClient(app) as c:
        assert c.get("/api/audit?key=desk-secret").status_code == 401
        locked = c.get("/ops?key=desk-secret")
        assert locked.status_code == 200
        assert "Unlock" in locked.text


def test_health_ok(client: TestClient):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["db"] == "ok"
    assert body["storage"] == "ok"
