# auditlink

## what it is

Tiny secure file share: upload -> tokenised link, optional passphrase, expiry, download cap, SHA-256 integrity, uploader revoke, ops desk, append-only audit log. Demo, not Dropbox.

## layout

```
auditlink/
  README.md
  NOTES.md                    # casual scratch
  app/
    main.py                   # routes + create_app()
    security.py               # tokens, pbkdf2, path guards, NoopScanner
    db.py                     # sqlite shares + audit_log
    cleanup.py                # drop expired / revoked / exhausted blobs
    rate_limit.py             # in-memory sliding window
    templates/                # jinja pages
    static/                   # css, icons, countdown.js
  tests/
  storage/                    # uploaded bytes (gitignored)
  requirements.txt
  pytest.ini
  Dockerfile
  docker-compose.yml
  .dockerignore
  .github/workflows/ci.yml    # pytest on push/PR
```

## quick start

```bash
cd auditlink
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# PROD / anything public: MUST set AUDIT_TOKEN before uvicorn.
# Unset = /api/audit and /ops are OPEN - demo/local/pytest only. Do not ship that.
export AUDIT_TOKEN='long-random-secret'
# optional fail-closed: refuse to start without AUDIT_TOKEN
# export AUDITLINK_ENV=prod

uvicorn app.main:app --reload --port 8000
# open http://127.0.0.1:8000
```

Optional Docker:

```bash
docker build -t auditlink .
docker run --rm -p 8000:8000 \
  -e AUDIT_TOKEN=change-me \
  -e AUDITLINK_ENV=prod \
  -v auditlink-data:/app/data \
  -v auditlink-files:/app/storage \
  auditlink
```

Or compose (requires `AUDIT_TOKEN` in the environment):

```bash
export AUDIT_TOKEN='long-random-secret'
docker compose up --build
```

Protect `/api/audit` when you care:

```bash
export AUDIT_TOKEN='long-random-secret'
curl -H "X-Audit-Token: $AUDIT_TOKEN" http://127.0.0.1:8000/api/audit
# or: Authorization: Bearer $AUDIT_TOKEN
```

**AUDIT_TOKEN:** if unset, `/api/audit` and `/ops` are open. That is demo/local/pytest only. Anything networked **must** set it - otherwise anyone can read the audit trail. Set `AUDITLINK_ENV=prod` to refuse start when the token is missing.

## stack

Python · FastAPI · SQLite · Jinja2 · Docker · pytest

## how its wired

```mermaid
flowchart TB
    subgraph client [Browser]
        U[Uploader]
        D[Downloader]
        M[Manage link]
        O[Ops desk]
    end

    subgraph auditlink [auditlink]
        API[FastAPI routes]
        RL[In-memory rate limiter]
        SEC[PBKDF2 + path guards + sha256]
        TPL[Jinja2 HTML]
    end

    subgraph persist [Disk]
        DB[(SQLite\nshares + audit_log)]
        FS[storage/\nrandom filenames]
    end

    U -->|POST /upload| API
    D -->|GET/POST /d/token| API
    M -->|GET/POST /m/manage| API
    O -->|GET /ops| API
    API --> RL
    API --> SEC
    API --> TPL
    API --> DB
    API --> FS
```

Upload streams bytes under `storage/` with a random name while hashing SHA-256. DB keeps original filename, download token, manage token, expiry, download budget, digest. Download checks rate limit -> revoked -> expiry -> max downloads -> passphrase -> hash match, then serves and logs. Manage link can revoke (delete blob). `/ops` is the audit console.

## whats interesting

- two tokens: download for the recipient, manage for the uploader (revoke)
- SHA-256 at upload; re-checked before serve (`hash_mismatch` in the audit log)
- tokenised links (`secrets.token_urlsafe`) - better than `/file/1`, `/file/2`
- passphrases hashed with pbkdf2 (260k iters) + `compare_digest`
- blobs never use the client path as the on-disk name; `resolve_under_storage` rejects `..`
- append-only `audit_log` (upload / download_success / download_denied / expired / rate_limited / revoked / hash_mismatch / cleanup)
- `/ops` desk with counts + filters; gated by `AUDIT_TOKEN` when set
- security headers (CSP, nosniff, frame-deny, referrer-policy)
- `NoopScanner` hook where clamav would plug in - architecture without pretending we scan malware
- cleanup drops blobs for expired / revoked shares (startup + `/ops/cleanup`)
- `/health` checks sqlite reachable + storage writable
- `AUDITLINK_ENV=prod` fails closed if `AUDIT_TOKEN` is unset

### threat model (keep in interviews)

- path traversal - blocked via `resolve_under_storage`
- brute force downloads - rate limit 20/min/IP; uploads and passphrase guesses have their own in-memory brakes
- link leakage - treat download *and* manage urls as secrets
- tamper / bit-rot - sha256 mismatch denies the download
- rate limit is in-memory - resets on restart, not multi-worker safe
- ops auth - header, Bearer, or unlock cookie only. no `?key=` query (would land in proxy logs / browser history)
- what we didn't do - no e2e encryption, no real malware scanning, no encryption at rest

## limitations

- **AUDIT_TOKEN must be set for anything networked.** unset = `/api/audit` and `/ops` wide open. that open mode is demo/local/pytest only. `AUDITLINK_ENV=prod` refuses to start without the token
- sqlite single-process - not multi-node
- rate limiter in ram (resets on restart; two workers = two counters) - covers download, upload, and passphrase spray
- no tls in-app - put a reverse proxy in front if you deploy
- ops unlock cookie is httponly; `Secure` only on https or when `AUDITLINK_SECURE_COOKIES=1` (plain http local demo keeps the cookie working)
- no accounts / org tenancy - link secrecy (+ optional passphrase) is the model
- max upload default 10 MB (`AUDITLINK_MAX_UPLOAD`)
- scanner is a no-op stub - swap in clamav yourself if you ever need it
- blobs are not encrypted at rest - disk access = file access

## tests

```bash
pytest -q
```

Named checks worth knowing: `test_expired_share_denied` -> expired link 410; `test_max_downloads` -> max downloads denied; `test_manage_revoke` -> revoke then 410; `test_hash_mismatch_denies` -> tampered blob 409.

## demo

```bash
uvicorn app.main:app --reload --port 8000
```

Open http://127.0.0.1:8000 - upload a file, copy share + manage links, try download / revoke, open `/ops`.
