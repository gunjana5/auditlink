auditlink

scratch notes - how this is glued together, nothing official


what this is

upload a file, get a /d/{token} link. optional passphrase, expiry (default 24h), max downloads (default 3). every attempt hits audit_log. meant to look like "i thought about the security bits" for cyber / ops placement apps, not a product.


layout in my head

app/main.py - routes only. create_app() so tests can pass tmp storage + db
app/security.py - tokens, pbkdf2, sanitize display name, resolve_under_storage
app/db.py - sqlite shares + audit_log, Share.is_expired / downloads_exhausted
app/rate_limit.py - sliding window deque per ip, in process ram
app/templates/ - upload / result / download, extends base.html
storage/ - gitignored blobs. random hex names. original filename only in the db


storage / random names

generate_storage_name keeps a sanitised extension for content-type vibes but the basename is secrets.token_hex(16). never write using the client path. resolve_under_storage refuses .. and path separators - if that ever raises, treat it as a bad request, don't "fix" it by joining naively


AUDIT_TOKEN

GET /api/audit is open when AUDIT_TOKEN env is empty. that's intentional for demos / pytest. for anything on a network set AUDIT_TOKEN and send X-Audit-Token or Authorization: Bearer. if someone clones this and deploys without reading the readme they'll leak the audit trail - say that in interviews, don't pretend it's locked down by default. prod MUST set it; open = demo only. readme screams this on purpose.


expiry countdown

download.html + result.html take expires_at (iso from the share row) and run a tiny js tick: "expires in Xh Ym", every minute, or every second once under 1h. if already expired, no countdown element.


rate limit

RateLimiter is 20 hits / 60s / ip by default (tests bump it). pure memory + threading.Lock. restart = empty. two uvicorn workers = two separate counters. fine for a coursework demo, not redis. download path logs rate_limited before returning 429


why max downloads

expiry alone still lets a shared link get hoovered forever inside the window. download_count vs max_downloads is a cheap second brake. once exhausted we 410 and log download_denied with max_downloads_reached. not cryptographic, just "stop after n pulls"


passphrase

optional. if set we store salt+hash only (pbkdf2 260k). blank passphrase = open link. verify uses compare_digest so i'm not doing a naive ==. wrong passphrase → 403 + audit, not a silent fail


download checks (order matters a bit)

1. rate limit
2. share exists
3. expired? (410 + expired event)
4. downloads exhausted?
5. passphrase if required
6. resolve path + file still on disk
7. increment + download_success + FileResponse

files are only read/written as bytes. never open them with a shell or import them as code. "dont exec uploads" is the whole point tbh


env knobs

AUDITLINK_DB - sqlite path (default ./auditlink.db)
AUDITLINK_STORAGE - blob dir (default ./storage)
AUDITLINK_MAX_UPLOAD - bytes (default 10mb)
AUDIT_TOKEN - protects /api/audit when set


stuff that bit me / remember later

macos / brew python - use .venv, don't pip --user into system
TestClient needs create_app with tmp_path or tests stomp the real db
Accept: application/json on upload returns json; browsers get the result.html page
x-forwarded-for first hop is what we call "ip" - trust only behind a proxy you control


quick mental map

upload → random blob + row + audit
/d/token get → page with status
/d/token post → checks → bytes
/api/audit → recent events (gate with AUDIT_TOKEN in anything real)

that's the loop when reopening this repo
