import hashlib
import hmac
import secrets
import threading


class KeyRing:
    """Retain the current signing key and at most two previous keys."""

    MAX_KEYS = 3

    def __init__(self):
        self._keys = {}
        self._lock = threading.Lock()
        self.active_kid = ''
        self.rotate()

    def rotate(self) -> str:
        with self._lock:
            # Fixed-size identifiers also avoid an ever-growing rotation counter.
            kid = secrets.token_hex(16)
            while kid in self._keys:
                kid = secrets.token_hex(16)
            self._keys[kid] = secrets.token_bytes(32)
            self.active_kid = kid
            while len(self._keys) > self.MAX_KEYS:
                del self._keys[next(iter(self._keys))]
            return kid

    def retire(self, kid: str) -> None:
        with self._lock:
            self._keys.pop(kid, None)
            if kid == self.active_kid:
                self.active_kid = next(reversed(self._keys), '')

    def sign(self, data: bytes, kid: str | None = None) -> tuple[str, bytes]:
        with self._lock:
            kid = kid or self.active_kid
            key = self._keys.get(kid)
            if key is None:
                raise KeyError('unknown kid')
            return kid, hmac.new(key, data, hashlib.sha256).digest()

    def verify(self, kid: str, data: bytes, signature: bytes) -> bool:
        with self._lock:
            key = self._keys.get(kid)
            return bool(key) and hmac.compare_digest(hmac.new(key, data, hashlib.sha256).digest(), signature)
