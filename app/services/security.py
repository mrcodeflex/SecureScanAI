"""Password hashing, session tokens, password policy and rate limiting."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from ..config import settings

_hasher = PasswordHasher()  # Argon2id with library defaults
DUMMY_HASH = _hasher.hash("securescan-dummy-password-for-timing")

_COMMON = {
    "password1234", "123456789012", "qwerty123456", "administrator", "letmein12345",
    "welcome12345", "changeme1234", "password12345", "securescanai1",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return False


def password_problems(password: str, username: str = "") -> list[str]:
    problems: list[str] = []
    if len(password) < 12:
        problems.append("Use at least 12 characters.")
    if len(password) > 128:
        problems.append("Use at most 128 characters.")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        problems.append("Include both letters and numbers.")
    if username and username.lower() in password.lower():
        problems.append("Do not include the username in the password.")
    if password.lower() in _COMMON:
        problems.append("This password is too common.")
    return problems


def generate_temp_password() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(16)) + str(secrets.randbelow(90) + 10)
        if not password_problems(pw):
            return pw


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Session tokens are stored as HMAC-SHA256 digests, never in plaintext."""
    return hmac.new(settings.secret_key.encode(), token.encode(), hashlib.sha256).hexdigest()


class RateLimiter:
    """Small in-memory sliding-window limiter (single-process deployment)."""

    def __init__(self, max_events: int, window_seconds: int):
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._events.setdefault(key, deque())
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def retry_after(self, key: str) -> int:
        """Seconds until the key may act again (0 = not blocked)."""
        now = time.monotonic()
        with self._lock:
            q = self._prune(key, now)
            if len(q) >= self.max_events:
                return max(1, int(self.window - (now - q[0])))
            return 0

    def hit(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(key, now).append(now)

    def consume(self, key: str) -> int:
        """Record an event if allowed. Returns 0 when allowed, else retry-after seconds."""
        wait = self.retry_after(key)
        if wait == 0:
            self.hit(key)
        return wait

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


login_user_limiter = RateLimiter(settings.login_max_attempts, settings.login_window_seconds)
login_ip_limiter = RateLimiter(settings.login_max_attempts * 4, settings.login_window_seconds)
scan_limiter = RateLimiter(settings.scans_per_minute, 60)
