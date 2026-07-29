# keep security checks in security.py / db.py

from __future__ import annotations

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
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.db import Database, utc_now
from app.rate_limit import RateLimiter
from app.security import (
    generate_storage_name,
    generate_token,
    hash_passphrase,
    resolve_under_storage,
    sanitize_display_name,
    verify_passphrase,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MAX_DOWNLOADS = 3
DEFAULT_EXPIRY_HOURS = 24


def create_app(
    *,
    storage_dir: Optional[Path] = None,
    db_path: Optional[Path] = None,
    audit_token: Optional[str] = None,
    max_upload_bytes: Optional[int] = None,
    rate_limit_max: int = 20,
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
    upload_cap = int(
        max_upload_bytes
        if max_upload_bytes is not None
        else os.environ.get("AUDITLINK_MAX_UPLOAD", 10 * 1024 * 1024)
    )

    db = Database(database_path)
    rate_limiter = RateLimiter(max_requests=rate_limit_max, window_seconds=60.0)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        storage.mkdir(parents=True, exist_ok=True)
        db.init()
        yield

    application = FastAPI(
        title="auditlink",
        description="Secure file share with expiry and append-only audit trail",
        version="1.0.0",
        lifespan=lifespan,
    )

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

    def require_audit_access(
        authorization: Optional[str] = Header(default=None),
        x_audit_token: Optional[str] = Header(default=None, alias="X-Audit-Token"),
    ) -> None:
        # unset AUDIT_TOKEN = audit api is open - demo only
        if not token_secret:
            return
        provided = x_audit_token
        if authorization and authorization.lower().startswith("bearer "):
            provided = authorization[7:].strip()
        if provided != token_secret:
            raise HTTPException(status_code=401, detail="Invalid or missing audit token")

    @application.get("/", response_class=HTMLResponse)
    async def home(request: Request):
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

        # stream in chunks so we don't blow ram on big uploads
        size = 0
        with dest.open("wb") as out:
            while True:
                chunk = await file.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > upload_cap:
                    out.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(
                        413,
                        f"File exceeds max upload size ({upload_cap} bytes)",
                    )
                out.write(chunk)

        # virus scan stub - would hook clamav / clamd here before create_share
        # skipped for this demo; never exec uploaded bytes either way

        salt_hex = hash_hex = None
        # passphrase optional - only store salt+hash, never the plaintext
        if passphrase.strip():
            salt_hex, hash_hex = hash_passphrase(passphrase.strip())

        # tokenised link + optional passphrase
        token = generate_token()
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
        )
        db.log_event(
            "upload",
            token=token,
            ip=client_ip(request),
            detail=f"filename={display_name}; size={size}",
        )

        share_url = str(request.url_for("download_page", token=token))
        accept = request.headers.get("accept", "")
        # json for api clients / tests, otherwise the html result page
        if "application/json" in accept:
            return JSONResponse(
                {
                    "token": token,
                    "url": share_url,
                    "expires_at": share.expires_at,
                    "max_downloads": share.max_downloads,
                    "requires_passphrase": share.requires_passphrase,
                }
            )

        return templates.TemplateResponse(
            request,
            "result.html",
            {
                "share_url": share_url,
                "token": token,
                "expires_at": share.expires_at,
                "max_downloads": share.max_downloads,
                "requires_passphrase": share.requires_passphrase,
                "filename": display_name,
            },
        )

    @application.get("/d/{token}", name="download_page", response_class=HTMLResponse)
    async def download_page(request: Request, token: str):
        share = db.get_share(token)
        if share is None:
            raise HTTPException(404, "Share not found")
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

        try:
            path = resolve_under_storage(storage, share.stored_name)
        except ValueError:
            db.log_event("download_denied", token=token, ip=ip, detail="bad_path")
            raise HTTPException(400, "Invalid file reference")

        if not path.is_file():
            db.log_event("download_denied", token=token, ip=ip, detail="missing_file")
            raise HTTPException(404, "File missing from storage")

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

    @application.get("/api/audit")
    async def api_audit(
        _: None = Depends(require_audit_access),
        limit: int = 100,
    ):
        limit = max(1, min(limit, 500))
        return {"events": db.recent_audit(limit=limit)}

    @application.get("/health")
    async def health():
        return {"status": "ok"}

    # stash bits on state so tests can poke the db / limiter
    application.state.db = db
    application.state.storage = storage
    application.state.rate_limiter = rate_limiter
    return application


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
