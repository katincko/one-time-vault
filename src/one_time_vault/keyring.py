"""Server keys for the password verifiers, with versions.

The browser sends a verifier (PBKDF2 of the password). The server never stores it: it stores
`HMAC-SHA256(server key, verifier)`, so a stolen database cannot be used to guess passwords
without the key, which lives in the environment. The stored value starts with a 5 byte header,
the key version and the PBKDF2 iteration count, so old secrets keep verifying after a rotation.
"""

import base64
import hashlib
import hmac
import re

MIN_ITERATIONS = 600_000  # OWASP floor for PBKDF2-HMAC-SHA256
MAX_ITERATIONS = 1_000_000  # the cost lands on the opener's browser, so it has a ceiling too
VERIFIER_BYTES = 32
MIN_KEY_BYTES = 32
HEADER_BYTES = 5  # key version (1) + iterations (4, big endian)
_ENTRY = re.compile(r"(\d{1,3}):([A-Za-z0-9_-]+)")


class KeyringError(ValueError):
    """The server keys are missing or malformed. Raised at boot, so the app never starts."""


class UnknownKeyVersion(RuntimeError):
    """A stored verifier was sealed by a key this server no longer has."""


class Keyring:
    def __init__(self, keys: dict[int, bytes], current: int) -> None:
        if current not in keys:
            raise KeyringError("current key version is not in the keyring")
        self._keys = keys
        self._current = current

    @classmethod
    def parse(cls, text: str | None) -> "Keyring":
        """`"2:<key>,1:<old key>"`: base64url keys of 32 bytes or more; the first is current."""
        if not text or not text.strip():
            raise KeyringError("OTV_SERVER_KEYS is required (format: 2:<base64url>,1:<base64url>)")
        keys: dict[int, bytes] = {}
        current: int | None = None
        for entry in text.split(","):
            match = _ENTRY.fullmatch(entry.strip())
            if not match:
                raise KeyringError("OTV_SERVER_KEYS entries must look like <version>:<base64url>")
            version = int(match.group(1))
            if not 1 <= version <= 255 or version in keys:
                raise KeyringError(f"key version {version} is out of 1..255 or repeated")
            raw = base64.urlsafe_b64decode(match.group(2) + "=" * (-len(match.group(2)) % 4))
            if len(raw) < MIN_KEY_BYTES:
                raise KeyringError(f"key {version} is shorter than {MIN_KEY_BYTES} bytes")
            keys[version] = raw
            current = version if current is None else current
        assert current is not None
        return cls(keys, current)

    def _mac(self, version: int, verifier: bytes) -> bytes:
        try:
            key = self._keys[version]
        except KeyError:
            raise UnknownKeyVersion(f"no server key for version {version}") from None
        return hmac.new(key, verifier, hashlib.sha256).digest()

    def seal(self, verifier: bytes, iterations: int) -> bytes:
        """What the server stores for a new password protected secret."""
        header = bytes([self._current]) + iterations.to_bytes(4, "big")
        return header + self._mac(self._current, verifier)

    def bind(self, stored: bytes, verifier: bytes) -> bytes:
        """What `stored` would be if `verifier` is the right one: same header, same key version."""
        return stored[:HEADER_BYTES] + self._mac(stored[0], verifier)


def iterations_of(stored: bytes) -> int:
    return int.from_bytes(stored[1:HEADER_BYTES], "big")
