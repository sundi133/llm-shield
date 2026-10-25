"""Portal passwords (docs/specs/password-sign-in.md, tasks 1 and 2).

One account per email address, shared by every workspace that address belongs
to (membership lives in storage/signup_store.py). A password is kept only as
a salted scrypt hash with its parameters, so they can be raised later and an
old hash upgraded at the next sign-in. Guessing is limited per account (a
lockout that doubles) and per address (a failure counter per 15 minutes).

Keys (Redis, or the in-memory fallback when there is none):

  useracct:{email_hash}          the account (JSON): email, password, set_at,
                                 last_sign_in, lock_count
  pwdfail:{email_hash}           wrong passwords since the last success or lock
  pwdlock:{email_hash}           {n, until} while the account is locked (TTL)
  pwdrate:ip:{ip_hash}:{window}  wrong passwords from one address, per 15 minutes
  pwdlink:{sha256(token)}        a set-password link (invite or reset), once
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import unicodedata
from typing import Optional

from storage import signup_store as _members
from storage import tenant_store as _ts

MIN_LENGTH, MAX_LENGTH = 12, 128
SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P = 15, 8, 1
LOCK_AFTER = 5
LOCK_BASE_S = 15 * 60
LOCK_MAX_S = 24 * 3600
IP_WINDOW_S = 15 * 60
IP_LIMIT = 20
CAPTCHA_AFTER = 3
RESET_TTL_S = 30 * 60
INVITE_TTL_S = 7 * 86400

_lock = threading.Lock()
_mem: dict = {}


def _r():
    return _ts._get_redis()


def _sha(v: str) -> str:
    return hashlib.sha256((v or "").encode("utf-8")).hexdigest()


def _now() -> int:
    return int(time.time())


def _decode(v):
    return v.decode() if isinstance(v, (bytes, bytearray)) else v


# ── hashing ──────────────────────────────────────────────────────────


def normalize(password: str) -> str:
    """NFKC, as NIST SP 800-63B asks, so the same password typed on two
    keyboards hashes the same."""
    return unicodedata.normalize("NFKC", password or "")


def _scrypt(password: str, salt: bytes, log2_n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(normalize(password).encode("utf-8"), salt=salt, n=2 ** log2_n,
                          r=r, p=p, dklen=32, maxmem=256 * 1024 * 1024)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = _scrypt(password, salt, SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P)
    b64 = lambda b: base64.b64encode(b).decode()            # noqa: E731
    return f"scrypt${SCRYPT_LOG2_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(key)}"


def verify_hash(password: str, stored: str) -> bool:
    try:
        scheme, log2_n, r, p, salt, key = stored.split("$")
        if scheme != "scrypt":
            return False
        got = _scrypt(password, base64.b64decode(salt), int(log2_n), int(r), int(p))
        return hmac.compare_digest(got, base64.b64decode(key))
    except (ValueError, TypeError):
        return False


def needs_rehash(stored: str) -> bool:
    return not stored.startswith(f"scrypt${SCRYPT_LOG2_N}${SCRYPT_R}${SCRYPT_P}$")


_DUMMY: Optional[str] = None


def burn_time(password: str) -> None:
    """Spend a real hash's time on an unknown email, so the reply time does
    not say whether an account exists."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password(secrets.token_urlsafe(16))
    verify_hash(password, _DUMMY)


# ── rules ────────────────────────────────────────────────────────────

# Words that, padded with digits and symbols, make most guessed passwords of
# this length. Checked as the whole password once digits and symbols are
# stripped, not as substrings, so a passphrase that merely contains one passes.
_COMMON_WORDS = {
    "password", "passw0rd", "welcome", "letmein", "iloveyou", "admin", "administrator",
    "qwerty", "monkey", "dragon", "sunshine", "football", "baseball", "princess",
    "master", "shadow", "superman", "batman", "trustno", "changeme", "default",
    "secret", "login", "access", "hello", "freedom", "whatever", "starwars", "summer",
    "winter", "spring", "autumn", "january", "february", "december", "computer",
    "internet", "michael", "jennifer", "jordan", "charlie", "abcdef", "abc",
    "votal", "shield", "votalshield", "test", "testing", "temp", "guest", "user",
}
_KEYBOARD = ("qwertyuiopasdfghjklzxcvbnm", "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
             "1234567890", "abcdefghijklmnopqrstuvwxyz")


def _is_run(s: str) -> bool:
    """The whole thing is one stretch of a keyboard row or the alphabet,
    forwards or backwards, possibly repeated."""
    for row in _KEYBOARD:
        for seq in (row, row[::-1]):
            for i in range(len(seq)):
                piece = seq[i:i + 4]
                if len(piece) == 4 and s.startswith(piece):
                    run = seq[i:]
                    if run.startswith(s) or (run * (len(s) // len(run) + 2)).startswith(s):
                        return True
    return False


def password_problem(password: str, *, email: str = "", names: tuple = ()) -> str:
    """Why this password is refused, or "" when it is acceptable."""
    pw = normalize(password)
    if len(pw) < MIN_LENGTH:
        return f"Use at least {MIN_LENGTH} characters."
    if len(pw) > MAX_LENGTH:
        return f"Use at most {MAX_LENGTH} characters."
    low = pw.lower()
    if len(set(low)) <= 2:
        return "Use more than one or two different characters."
    for size in range(1, len(low) // 2 + 1):
        if len(low) % size == 0 and low == low[:size] * (len(low) // size):
            return "Do not repeat the same part over and over."
    letters = re.sub(r"[^a-z]", "", low)
    if letters in _COMMON_WORDS or (not letters and _is_run(re.sub(r"[^0-9]", "", low))):
        return "That is one of the most commonly guessed passwords."
    if _is_run(low) or _is_run(re.sub(r"[^a-z0-9]", "", low)):
        return "Do not use a keyboard row or a sequence."
    local = (email or "").split("@")[0].lower()
    if len(local) >= 4 and local in low:
        return "Do not use your email address in your password."
    for name in names:
        n = re.sub(r"[^a-z0-9]", "", (name or "").lower())
        if len(n) >= 4 and n in re.sub(r"[^a-z0-9]", "", low):
            return "Do not use your workspace's name in your password."
    return ""


# ── accounts ─────────────────────────────────────────────────────────


def _get(key: str):
    r = _r()
    return _decode(_mem.get(key) if r is None else r.get(key))


def _set(key: str, value: str, ttl: Optional[int] = None, nx: bool = False) -> bool:
    r = _r()
    if r is None:
        with _lock:
            if nx and key in _mem:
                return False
            _mem[key] = value
        return True
    return bool(r.set(key, value, ex=ttl, nx=nx))


def _delete(*keys: str) -> None:
    r = _r()
    if r is None:
        with _lock:
            for k in keys:
                _mem.pop(k, None)
        return
    r.delete(*keys)


def _incr(key: str, ttl: Optional[int] = None) -> int:
    r = _r()
    if r is None:
        with _lock:
            _mem[key] = int(_mem.get(key) or 0) + 1
            return _mem[key]
    n = int(r.incr(key))
    if ttl and n == 1:
        r.expire(key, ttl)
    return n


def get_account(email: str) -> Optional[dict]:
    raw = _get(f"useracct:{_members.email_hash(email)}")
    try:
        rec = json.loads(raw) if raw else None
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def _save_account(email: str, rec: dict) -> None:
    _set(f"useracct:{_members.email_hash(email)}", json.dumps(rec))


def has_password(email: str) -> bool:
    return bool((get_account(email) or {}).get("password"))


def set_password(email: str, password: str) -> None:
    """Store a new password (already checked) and clear any lockout."""
    email = _members.normalize_email(email)
    rec = get_account(email) or {"email": email}
    rec.update(password=hash_password(password), set_at=_now(), lock_count=0)
    _save_account(email, rec)
    clear_failures(email)


def check_password(email: str, password: str) -> bool:
    """True if the password is this account's. Upgrades an old hash. Counts
    nothing: the caller records the outcome (record_failure, record_success)."""
    rec = get_account(email)
    if not rec or not rec.get("password"):
        burn_time(password)
        return False
    if not verify_hash(password, rec["password"]):
        return False
    if needs_rehash(rec["password"]):
        rec["password"] = hash_password(password)
        _save_account(email, rec)
    return True


def is_locked(email: str) -> bool:
    """Whether the account is locked now. The lock carries its own deadline:
    the in-memory fallback keeps keys past their TTL."""
    raw = _get(f"pwdlock:{_members.email_hash(email)}")
    try:
        return bool(raw) and float(json.loads(raw).get("until", 0)) > time.time()
    except (ValueError, AttributeError):
        return False


def record_failure(email: str) -> bool:
    """Count a wrong password. True if this one locked the account. A lockout
    lasts 15 minutes, doubling with each further one, up to 24 hours."""
    eh = _members.email_hash(email)
    if _incr(f"pwdfail:{eh}") < LOCK_AFTER:
        return False
    rec = get_account(email) or {}
    n = int(rec.get("lock_count") or 0)
    seconds = min(LOCK_BASE_S * (2 ** n), LOCK_MAX_S)
    if not is_locked(email):
        _delete(f"pwdlock:{eh}")                 # an expired lock the fallback kept
    # Two wrong passwords racing past the limit lock once, not twice.
    if not _set(f"pwdlock:{eh}", json.dumps({"n": n + 1, "until": time.time() + seconds}),
                ttl=seconds, nx=True):
        return False
    _delete(f"pwdfail:{eh}")
    if rec:
        rec["lock_count"] = n + 1
        _save_account(email, rec)
    return True


def clear_failures(email: str) -> None:
    eh = _members.email_hash(email)
    _delete(f"pwdfail:{eh}", f"pwdlock:{eh}")


def record_success(email: str) -> None:
    clear_failures(email)
    rec = get_account(email)
    if rec:
        rec.update(last_sign_in=_now(), lock_count=0)
        _save_account(email, rec)


# ── per address ──────────────────────────────────────────────────────


def _ip_key(ip: str) -> str:
    return f"pwdrate:ip:{_sha(ip)[:32]}:{_now() // IP_WINDOW_S}"


def ip_failures(ip: str) -> int:
    try:
        return int(_get(_ip_key(ip)) or 0)
    except ValueError:
        return 0


def record_ip_failure(ip: str) -> int:
    return _incr(_ip_key(ip), ttl=2 * IP_WINDOW_S)


# ── set-password links ───────────────────────────────────────────────
# One-time records with their own deadline, kept the way sign-up keeps its
# tokens (signup_store._put/_take/_peek: hash only, read-and-delete).


def new_link(email: str, *, purpose: str, tenant_id: str = "") -> str:
    token, tok_hash = _members.new_token()
    ttl = INVITE_TTL_S if purpose == "invite" else RESET_TTL_S
    _members._put(f"pwdlink:{tok_hash}", {"email": _members.normalize_email(email),
                                          "purpose": purpose, "tenant_id": tenant_id}, ttl)
    return token


def peek_link(token: str) -> Optional[dict]:
    return _members._peek(f"pwdlink:{_members.token_hash(token)}") if token else None


def take_link(token: str) -> Optional[dict]:
    return _members._take(f"pwdlink:{_members.token_hash(token)}") if token else None


def reset_for_tests() -> None:
    global _DUMMY
    with _lock:
        _mem.clear()
    _DUMMY = None
