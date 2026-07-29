# keep security checks in security.py / db.py

from __future__ import annotations

import hashlib
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import AsyncIterator, Optional

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.cleanup import cleanup_expired
from app.db import Database, utc_now
from app.rate_limit import RateLimiter
from app.security import (
    NoopScanner,
    file_sha256,
    generate_storage_name,
    generate_token,
    hash_passphrase,
    resolve_under_storage,
    sanitize_display_name,
    short_hash,
    verify_passphrase,
)

BASE_DIR = Path(__file__).resolve().parent.parent
# defaults for the form + api
DEFAULT_MAX_DOWNLOADS = 3
DEFAULT_EXPIRY_HOURS = 24
OPS_COOKIE = "auditlink_ops"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # fonts from google; everything else self
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'"
        )
        return response


def create_app(
    *,
    storage_dir: Optional[Path] = None,
    db_path: Optional[Path] = None,
    audit_token: Optional[str] = None,
    max_upload_bytes: Optional[int] = None,
    rate_limit_max: int = 20,
    run_cleanup_on_start: bool = True,
) -> FastAPI:
    # env overrides so docker / tests can point at tmp dirs
    storage = Path(
        storage_dir
        or os.environ.get("AUDITLINK_STORAGE", BASE_DIR / "storage")
    )
    database_path = Path(
        db_path or os.environ.get("AUDITLINK_DB", BASE_DIR / "auditlink.db")
    )
    token_secret = (
        audit_token
        if audit_token is not None
        else os.environ.get("AUDIT_TOKEN", "")
    )
    # 10 MiB default - enough for demos, not for dumping huge archives
    upload_cap = int(
        max_upload_bytes
        if max_upload_bytes is not None
        else os.environ.get("AUDITLINK_MAX_UPLOAD", 10 * 1024 * 1024)
    )

    db = Database(database_path)
    rate_limiter = RateLimiter(max_requests=rate_limit_max, window_seconds=60.0)
    scanner = NoopScanner()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # make sure dirs / schema exist before the first request
        storage.mkdir(parents=True, exist_ok=True)
        db.init()
        if run_cleanup_on_start:
            cleanup_expired(storage, db)
        yield

    application = FastAPI(
        title="auditlink",
        description="Secure file share with expiry and append-only audit trail",
        version="1.1.0",
        lifespan=lifespan,
    )
    application.add_middleware(SecurityHeadersMiddleware)

    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
    static_dir = Path(__file__).parent / "static"
    application.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def client_ip(request: Request) -> str:
        # trust first hop if behind a proxy - fine for demo
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    def _provided_audit_secret(
        request: Request,
        authorization: Optional[str],
        x_audit_token: Optional[str],
    ) -> Optional[str]:
        provided = x_audit_token
        if authorization and authorization.lower().startswith("bearer "):
            provided = authorization[7:].strip()
        if not provided:
            provided = request.cookies.get(OPS_COOKIE)
        if not provided:
            provided = request.query_params.get("key")
        return provided

    def require_audit_access(
        request: Request,
        authorization: Optional[str] = Header(default=None),
        x_audit_token: Optional[str] = Header(default=None, alias="X-Audit-Token"),
    ) -> None:
        # unset AUDIT_TOKEN = audit api is open - demo only
        if not token_secret:
            return
        provided = _provided_audit_secret(request, authorization, x_audit_token)
        if provided != token_secret:
            raise HTTPException(status_code=401, detail="Invalid or missing audit token")

    def audit_unlocked(request: Request) -> bool:
        if not token_secret:
            return True
        return _provided_audit_secret(request, None, None) == token_secret

    @application.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        # upload form - defaults match the constants above
        return templates.TemplateResponse(
            request,
            "upload.html",
            {
                "default_expiry_hours": DEFAULT_EXPIRY_HOURS,
                "default_max_downloads": DEFAULT_MAX_DOWNLOADS,
                "max_upload_mb": upload_cap // (1024 * 1024),
            },
        )

    @application.post("/upload")
    async def upload_file(
        request: Request,
        file: UploadFile = File(...),
        passphrase: str = Form(default=""),
        expiry_hours: int = Form(default=DEFAULT_EXPIRY_HOURS),
        max_downloads: int = Form(default=DEFAULT_MAX_DOWNLOADS),
    ):
        # clamp form values so nobody sets expiry to a century
        if expiry_hours < 1 or expiry_hours > 24 * 30:
            raise HTTPException(400, "expiry_hours must be between 1 and 720")
        if max_downloads < 1 or max_downloads > 100:
            raise HTTPException(400, "max_downloads must be between 1 and 100")

        raw_name = file.filename or "upload.bin"
        display_name = sanitize_display_name(raw_name)
        stored_name = generate_storage_name(display_name)
        try:
            dest = resolve_under_storage(storage, stored_name)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

        # stream + hash in one pass so we don't re-read for sha256
        size = 0
        hasher = hashlib.sha256()
        with dest.open("wb") as out:
            while True:
                chunk = await file.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > upload_cap:
                    # wipe the partial file so storage doesn't fill with junk
                    out.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(
                        413,
                        f"File exceeds max upload size ({upload_cap} bytes)",
                    )
                hasher.update(chunk)
                out.write(chunk)

        content_digest = hasher.hexdigest()
        # scanner hook - NoopScanner today; swap in clamav later without route rewrites
        scanner.scan(dest)

        salt_hex = hash_hex = None
        # passphrase optional - only store salt+hash, never the plaintext
        if passphrase.strip():
            salt_hex, hash_hex = hash_passphrase(passphrase.strip())

        # download token for the recipient; manage token stays with the uploader
        token = generate_token()
        manage_token = generate_token()
        expires_at = utc_now() + timedelta(hours=expiry_hours)
        share = db.create_share(
            token=token,
            original_filename=display_name,
            stored_name=stored_name,
            content_type=file.content_type,
            size_bytes=size,
            passphrase_salt=salt_hex,
            passphrase_hash=hash_hex,
            expires_at=expires_at,
            max_downloads=max_downloads,
            content_sha256=content_digest,
            manage_token=manage_token,
        )
        db.log_event(
            "upload",
            token=token,
            ip=client_ip(request),
            detail=f"filename={display_name}; size={size}; sha256={short_hash(content_digest)}",
        )

        share_url = str(request.url_for("download_page", token=token))
        manage_url = str(request.url_for("manage_page", manage_token=manage_token))
        accept = request.headers.get("accept", "")
        # json for api clients / tests, otherwise the html result page
        if "application/json" in accept:
            return JSONResponse(
                {
                    "token": token,
                    "url": share_url,
                    "manage_token": manage_token,
                    "manage_url": manage_url,
                    "expires_at": share.expires_at,
                    "max_downloads": share.max_downloads,
                    "requires_passphrase": share.requires_passphrase,
                    "content_sha256": content_digest,
                }
            )

        return templates.TemplateResponse(
            request,
            "result.html",
            {
                "share_url": share_url,
                "manage_url": manage_url,
                "token": token,
                "expires_at": share.expires_at,
                "max_downloads": share.max_downloads,
                "requires_passphrase": share.requires_passphrase,
                "filename": display_name,
                "content_sha256": content_digest,
                "sha_short": short_hash(content_digest),
            },
        )

    @application.get("/d/{token}", name="download_page", response_class=HTMLResponse)
    async def download_page(request: Request, token: str):
        # landing page - passphrase form if needed, or dead state
        share = db.get_share(token)
        if share is None:
            raise HTTPException(404, "Share not found")
        status = share.status_label()
        return templates.TemplateResponse(
            request,
            "download.html",
            {
                "token": token,
                "filename": share.original_filename,
                "requires_passphrase": share.requires_passphrase,
                "expires_at": share.expires_at,
                "downloads_left": max(0, share.max_downloads - share.download_count),
                "expired": share.is_expired(),
                "exhausted": share.downloads_exhausted(),
                "revoked": share.is_revoked(),
                "status": status,
                "sha_short": short_hash(share.content_sha256),
                "content_sha256": share.content_sha256 or "",
            },
        )

    @application.post("/d/{token}")
    async def download_file(
        request: Request,
        token: str,
        passphrase: str = Form(default=""),
    ):
        ip = client_ip(request)
        # rate limit first - cheap, stops hammering before we touch the db much
        if not rate_limiter.allow(ip):
            db.log_event("rate_limited", token=token, ip=ip, detail="download")
            raise HTTPException(
                429, "Too many download attempts from this IP. Try again shortly."
            )

        share = db.get_share(token)
        if share is None:
            db.log_event("download_denied", token=token, ip=ip, detail="not_found")
            raise HTTPException(404, "Share not found")

        if share.is_revoked():
            db.log_event("download_denied", token=token, ip=ip, detail="revoked")
            raise HTTPException(410, "This share has been revoked")

        # expiry check - 410 so clients don't keep retrying forever
        if share.is_expired():
            db.log_event("expired", token=token, ip=ip, detail="past_expires_at")
            db.log_event("download_denied", token=token, ip=ip, detail="expired")
            raise HTTPException(410, "This share has expired")

        if share.downloads_exhausted():
            db.log_event(
                "download_denied",
                token=token,
                ip=ip,
                detail="max_downloads_reached",
            )
            raise HTTPException(410, "Download limit reached for this share")

        if share.requires_passphrase:
            # wrong / missing passphrase - 403, not 401 (no login flow)
            if not passphrase or not verify_passphrase(
                passphrase,
                share.passphrase_salt or "",
                share.passphrase_hash or "",
            ):
                db.log_event(
                    "download_denied",
                    token=token,
                    ip=ip,
                    detail="bad_passphrase",
                )
                raise HTTPException(403, "Incorrect passphrase")

        if not share.stored_name:
            db.log_event("download_denied", token=token, ip=ip, detail="missing_file")
            raise HTTPException(404, "File missing from storage")

        try:
            path = resolve_under_storage(storage, share.stored_name)
        except ValueError:
            db.log_event("download_denied", token=token, ip=ip, detail="bad_path")
            raise HTTPException(400, "Invalid file reference")

        if not path.is_file():
            # db row exists but blob gone - treat as missing
            db.log_event("download_denied", token=token, ip=ip, detail="missing_file")
            raise HTTPException(404, "File missing from storage")

        # integrity check before we hand bytes back
        if share.content_sha256:
            actual = file_sha256(path)
            if actual != share.content_sha256:
                db.log_event(
                    "hash_mismatch",
                    token=token,
                    ip=ip,
                    detail=f"expected={short_hash(share.content_sha256)} actual={short_hash(actual)}",
                )
                db.log_event(
                    "download_denied",
                    token=token,
                    ip=ip,
                    detail="hash_mismatch",
                )
                raise HTTPException(409, "File integrity check failed")

        # bump count then hand the file back - audit after so we have a trail
        db.increment_download(token)
        db.log_event(
            "download_success",
            token=token,
            ip=ip,
            detail=share.original_filename,
        )

        return FileResponse(
            path,
            filename=share.original_filename,
            media_type=share.content_type or "application/octet-stream",
        )

    @application.get("/m/{manage_token}", name="manage_page", response_class=HTMLResponse)
    async def manage_page(request: Request, manage_token: str):
        share = db.get_share_by_manage_token(manage_token)
        if share is None:
            raise HTTPException(404, "Manage link not found")
        share_url = str(request.url_for("download_page", token=share.token))
        return templates.TemplateResponse(
            request,
            "manage.html",
            {
                "manage_token": manage_token,
                "share_url": share_url,
                "token": share.token,
                "filename": share.original_filename,
                "expires_at": share.expires_at,
                "max_downloads": share.max_downloads,
                "download_count": share.download_count,
                "downloads_left": max(0, share.max_downloads - share.download_count),
                "requires_passphrase": share.requires_passphrase,
                "status": share.status_label(),
                "revoked": share.is_revoked(),
                "sha_short": short_hash(share.content_sha256),
                "content_sha256": share.content_sha256 or "",
            },
        )

    @application.post("/m/{manage_token}/revoke")
    async def revoke_share(request: Request, manage_token: str):
        share = db.get_share_by_manage_token(manage_token)
        if share is None:
            raise HTTPException(404, "Manage link not found")
        if share.is_revoked():
            return RedirectResponse(
                url=str(request.url_for("manage_page", manage_token=manage_token)),
                status_code=303,
            )

        # drop blob first, then mark revoked
        if share.stored_name:
            try:
                path = resolve_under_storage(storage, share.stored_name)
                if path.is_file():
                    path.unlink(missing_ok=True)
            except ValueError:
                pass
            db.clear_stored_name(share.token)

        db.revoke_share(share.token)
        db.log_event(
            "revoked",
            token=share.token,
            ip=client_ip(request),
            detail="uploader_revoke",
        )
        accept = request.headers.get("accept", "")
        if "application/json" in accept:
            return JSONResponse({"ok": True, "token": share.token, "status": "revoked"})
        return RedirectResponse(
            url=str(request.url_for("manage_page", manage_token=manage_token)),
            status_code=303,
        )

    @application.get("/ops", response_class=HTMLResponse)
    async def ops_desk(
        request: Request,
        event_type: str = "",
        token_prefix: str = "",
        limit: int = 100,
    ):
        unlocked = audit_unlocked(request)
        demo_open = not bool(token_secret)
        if not unlocked:
            return templates.TemplateResponse(
                request,
                "ops.html",
                {
                    "locked": True,
                    "demo_open": False,
                    "events": [],
                    "counts": {},
                    "event_type": event_type,
                    "token_prefix": token_prefix,
                    "limit": limit,
                },
            )

        limit = max(1, min(limit, 500))
        events = db.recent_audit(
            limit=limit,
            event_type=event_type or None,
            token_prefix=token_prefix.strip() or None,
        )
        return templates.TemplateResponse(
            request,
            "ops.html",
            {
                "locked": False,
                "demo_open": demo_open,
                "events": events,
                "counts": db.audit_counts(),
                "event_type": event_type,
                "token_prefix": token_prefix,
                "limit": limit,
            },
        )

    @application.post("/ops/unlock")
    async def ops_unlock(request: Request, key: str = Form(...)):
        if not token_secret or key != token_secret:
            raise HTTPException(401, "Invalid audit token")
        resp = RedirectResponse(url="/ops", status_code=303)
        resp.set_cookie(
            OPS_COOKIE,
            key,
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 8,
        )
        return resp

    @application.post("/ops/cleanup")
    async def ops_cleanup(
        request: Request,
        _: None = Depends(require_audit_access),
    ):
        removed = cleanup_expired(storage, db)
        accept = request.headers.get("accept", "")
        if "application/json" in accept:
            return JSONResponse({"removed": removed})
        return RedirectResponse(url="/ops", status_code=303)

    @application.get("/api/audit")
    async def api_audit(
        request: Request,
        _: None = Depends(require_audit_access),
        limit: int = 100,
        event_type: str = "",
        token_prefix: str = "",
    ):
        # clamp so nobody asks for a million rows
        limit = max(1, min(limit, 500))
        return {
            "events": db.recent_audit(
                limit=limit,
                event_type=event_type or None,
                token_prefix=token_prefix.strip() or None,
            ),
            "counts": db.audit_counts(),
        }

    @application.get("/health")
    async def health():
        return {"status": "ok"}

    # stash bits on state so tests can poke the db / limiter
    application.state.db = db
    application.state.storage = storage
    application.state.rate_limiter = rate_limiter
    application.state.audit_token = token_secret
    return application


app = create_app()


if __name__ == "__main__":
    import uvicorn

    # reload for local tinkering - production would skip that
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
