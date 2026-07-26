# dont exec uploads, ever

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path

PBKDF2_ITERATIONS = 260_000
SALT_BYTES = 16


def generate_token() -> str:
    """URL-safe opaque share token."""
    return secrets.token_urlsafe(32)


def generate_storage_name(original_filename: str) -> str:
    # random on-disk name; keep a sanitised ext for content-type hints only
    ext = Path(original_filename).suffix.lower()
    if not re.fullmatch(r"\.[a-z0-9]{1,12}", ext or ""):
        ext = ""
    return f"{secrets.token_hex(16)}{ext}"


def sanitize_display_name(filename: str) -> str:
    """Strip path components; keep a safe display name for Content-Disposition."""
    name = Path(filename).name  # drops any directory traversal
    name = name.replace("\x00", "")
    name = re.sub(r"[^\w.\- ()\[\]]+", "_", name).strip(" .")
    return name[:200] or "download.bin"


def hash_passphrase(passphrase: str, salt: bytes | None = None) -> tuple[str, str]:
    """Return (hex_salt, hex_hash) using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return salt.hex(), digest.hex()


def verify_passphrase(passphrase: str, salt_hex: str, hash_hex: str) -> bool:
    # compare_digest - don't leak via timing on a naive ==
    salt = bytes.fromhex(salt_hex)
    _, candidate = hash_passphrase(passphrase, salt=salt)
    return hmac.compare_digest(candidate, hash_hex)


def resolve_under_storage(storage_dir: Path, stored_name: str) -> Path:
    # reject .. / separators; blob path must stay under storage/
    if not stored_name or stored_name != Path(stored_name).name:
        raise ValueError("Invalid storage name")
    if ".." in stored_name or "/" in stored_name or "\\" in stored_name:
        raise ValueError("Invalid storage name")

    storage_root = storage_dir.resolve()
    target = (storage_root / stored_name).resolve()
    if not str(target).startswith(str(storage_root) + os.sep) and target != storage_root:
        raise ValueError("Path escapes storage root")
    return target
