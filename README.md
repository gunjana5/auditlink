# auditlink

## what it is

Tiny secure file share: upload -> tokenised link, optional passphrase, expiry, download cap, SHA-256 integrity, uploader revoke, ops desk, append-only audit log. Demo, not Dropbox.

## layout

```
auditlink/
  README.md
  NOTES.md           # scratch for future me
  app/               # fastapi
  tests/
  storage/           # uploaded bytes (gitignored)
  Dockerfile
```

## quick start

```bash
cd auditlink
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# PROD / anything public: MUST set AUDIT_TOKEN before uvicorn.
# Unset = /api/audit and /ops are OPEN - demo/local only. Do not ship that.
export AUDIT_TOKEN='long-random-secret'

uvicorn app.main:app --reload --port 8000
# open http://127.0.0.1:8000
```

Optional Docker:

```bash
docker build -t auditlink .
docker run --rm -p 8000:8000 \
  -e AUDIT_TOKEN=change-me \
  -v auditlink-data:/app/data \
  -v auditlink-files:/app/storage \
  auditlink
```

Protect `/api/audit` when you care:

```bash
export AUDIT_TOKEN='long-random-secret'
curl -H "X-Audit-Token: $AUDIT_TOKEN" http://127.0.0.1:8000/api/audit
```

**AUDIT_TOKEN:** if unset, `/api/audit` and `/ops` are open. That is demo-only. Production **must** set it - otherwise anyone can read the audit trail.

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

### threat model (keep in interviews)

- path traversal - blocked via `resolve_under_storage`
- brute force downloads - rate limit 20/min/IP
- link leakage - treat download *and* manage urls as secrets
- tamper / bit-rot - sha256 mismatch denies the download
- rate limit is in-memory - resets on restart, not multi-worker safe
- what we didn't do - no e2e encryption, no real malware scanning

## limitations

- **AUDIT_TOKEN must be set in prod.** unset = `/api/audit` and `/ops` wide open. that open mode is demo-only
- sqlite single-process - not multi-node
- rate limiter in ram (resets on restart; two workers = two counters)
- no tls in-app - put a reverse proxy in front if you deploy
- no accounts / org tenancy - link secrecy (+ optional passphrase) is the model
- max upload default 10 MB (`AUDITLINK_MAX_UPLOAD`)
- scanner is a no-op stub - swap in clamav yourself if you ever need it

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
