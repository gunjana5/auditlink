auditlink

scratch notes - how this is glued together, nothing official


what this is

upload a file, get a /d/{token} share link + a /m/{manage_token} manage link.
optional passphrase, expiry (default 24h), max downloads (default 3), sha256 on the blob.
every attempt hits audit_log. /ops is the audit desk.
meant to look like "i thought about the security bits" for cyber / ops placement apps, not a product.


layout in my head

app/main.py - routes only. create_app() so tests can pass tmp storage + db
app/security.py - tokens, pbkdf2, sanitize display name, resolve_under_storage, file_sha256, NoopScanner
app/db.py - sqlite shares + audit_log, Share status helpers, audit filters/counts
app/cleanup.py - drop blobs for expired/revoked/exhausted shares
app/rate_limit.py - sliding window deque per ip, in process ram
app/templates/ - upload / result / download / manage / ops, extends base.html
app/static/countdown.js - shared expiry tick for result + download pages
storage/ - gitignored blobs. random hex names. original filename only in the db


two tokens

download token (/d/...) - give this to the recipient
manage token (/m/...) - keep this. revoke deletes the blob and sets revoked_at.
never put manage_token on the public download page. interview line: "download token is for them, manage token stays with me"


sha256

hashed while streaming the upload (one pass). stored as content_sha256.
before FileResponse we re-hash; mismatch -> 409 + hash_mismatch audit + download_denied.
not encryption - just integrity / tamper detection


storage / random names

generate_storage_name keeps a sanitised extension for content-type vibes but the basename is secrets.token_hex(16). never write using the client path. resolve_under_storage refuses .. and path separators - if that ever raises, treat it as a bad request, don't "fix" it by joining naively


AUDIT_TOKEN

GET /api/audit and GET /ops are open when AUDIT_TOKEN env is empty. intentional for demos / pytest.
for anything on a network set AUDIT_TOKEN. api wants X-Audit-Token or Authorization: Bearer.
ops desk: unlock form sets an httponly cookie (Secure when https or AUDITLINK_SECURE_COOKIES=1).
plain http local demo: cookie works without Secure so unlock still sticks - fine for 127.0.0.1.
no ?key= query auth - that would leak into proxy logs / browser history / Referer.
if someone clones this and deploys without reading the readme they'll leak the audit trail - say that in interviews. prod MUST set it; open = demo only.

AUDITLINK_ENV=prod (or production) refuses to start if AUDIT_TOKEN is empty. default / unset leaves open mode for demos and pytest. docker-compose example sets the token; bare image alone does not fail closed.


scanner stub

NoopScanner.scan(path) is called after the blob lands, before create_share.
swap in clamav / clamd later without rewriting routes. do not pretend we scan malware in demos.


cleanup

cleanup_expired() deletes blobs for expired, revoked, or exhausted (download_count >= max_downloads) shares that still have a stored_name, clears stored_name, logs cleanup.
runs once on startup (unless tests pass run_cleanup_on_start=False) and from POST /ops/cleanup.
share row stays so audit still joins on token.


expiry countdown

download.html + result.html share app/static/countdown.js: "expires in Xh Ym", every minute, or every second once under 1h. if already expired / revoked, no countdown element.


rate limit

RateLimiter is in-process ram + threading.Lock. restart = empty. two uvicorn workers = two separate counters. fine for a coursework demo, not redis.
download path: 20 / 60s / ip by default (tests bump it). logs rate_limited before 429.
upload path: 10 / 60s / ip (upload:{ip}).
passphrase spray: 10 failed guesses / 60s / ip (pass:{ip}) before 429.


why max downloads

expiry alone still lets a shared link get hoovered forever inside the window. download_count vs max_downloads is a cheap second brake. early exhausted check is for the obvious case; try_increment_download does an atomic UPDATE ... WHERE download_count < max_downloads so concurrent pulls can't overshoot. False -> 410 + max_downloads_reached. not cryptographic, just "stop after n pulls"


passphrase

optional. if set we store salt+hash only (pbkdf2 260k). blank passphrase = open link. verify uses compare_digest so i'm not doing a naive ==. wrong passphrase -> 403 + audit, not a silent fail


download checks (order matters a bit)

1. rate limit
2. share exists
3. revoked?
4. expired? (410 + expired event)
5. downloads exhausted? (fast path)
6. passphrase if required (spray brake on bad guesses)
7. resolve path + file still on disk
8. sha256 match
9. try_increment_download (atomic) - False = exhausted; then download_success + FileResponse

files are only read/written as bytes. never open them with a shell or import them as code. "dont exec uploads" is the whole point tbh


/health

GET /health runs SELECT 1 on sqlite and a write/unlink probe under storage/. 200 with status ok, or 503 if either fails.


env knobs

AUDITLINK_DB - sqlite path (default ./auditlink.db)
AUDITLINK_STORAGE - blob dir (default ./storage)
AUDITLINK_MAX_UPLOAD - bytes (default 10mb)
AUDIT_TOKEN - protects /api/audit + /ops when set
AUDITLINK_ENV - prod/production = refuse start without AUDIT_TOKEN
AUDITLINK_SECURE_COOKIES - 1/true/yes = force Secure on the ops unlock cookie


docker

image runs as uid 10001 (auditlink). set AUDIT_TOKEN; for fail-closed also AUDITLINK_ENV=prod.
compose needs AUDIT_TOKEN in your shell env (no default secret in the yaml).
if named volumes make storage unwritable for non-root, chown 10001:10001 on the volume once.


stuff that bit me / remember later

macos / brew python - use .venv, don't pip --user into system
TestClient needs create_app with tmp_path or tests stomp the real db
Accept: application/json on upload returns json; browsers get the result.html page
x-forwarded-for first hop is what we call "ip" - trust only behind a proxy you control
old sqlite dbs need the migrate ALTER for content_sha256 / manage_token / revoked_at - init() does that
AUDIT_TOKEN compare uses compare_digest now - don't regress to !=


future

- clamav behind the Scanner Protocol (optional, documented, Noop by default) - only if it can work without heavy ops pain
- encrypt blobs at rest with a key from env - only if custody limits stay honest; otherwise leave as-is and say so in interviews


quick mental map

upload -> random blob + sha256 + manage_token + audit
/d/token get -> page with status chips
/d/token post -> checks -> bytes
/m/manage -> status + revoke
/ops -> audit desk
/api/audit -> json events (gate with AUDIT_TOKEN in anything real)
/health -> db + storage probe

that's the loop when reopening this repo
