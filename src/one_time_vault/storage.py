"""Redis/Valkey storage for one-time secrets.

Missing, already read and expired secrets are the same thing here: `NotFound`.
"""

import base64
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from one_time_vault import scripts

MAX_ATTEMPTS = 5
KEY_PREFIX = "ovv:s:"
ID_BYTES = 16  # 128 bits
ID_LENGTH = 22  # base64url of 16 bytes, no padding
_ID_RETRIES = 5


def new_secret_id() -> str:
    """128 random bits, base64url. Ids are always made here, never taken from a caller."""
    return base64.urlsafe_b64encode(secrets.token_bytes(ID_BYTES)).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class Revealed:
    payload: bytes


@dataclass(frozen=True)
class NotFound:
    """Never existed, already read, expired or destroyed by wrong passwords."""


@dataclass(frozen=True)
class PasswordRequired:
    """Protected secret opened without a verifier. Not counted as an attempt."""


@dataclass(frozen=True)
class WrongPassword:
    attempts_left: int  # 0 means the secret was just destroyed


OpenResult = Revealed | NotFound | PasswordRequired | WrongPassword


class SecretStorage:
    def __init__(self, redis: Redis, *, max_attempts: int = MAX_ATTEMPTS) -> None:
        self._max_attempts = max_attempts
        self._create = redis.register_script(scripts.CREATE)
        self._peek = redis.register_script(scripts.PEEK_VERIFIER)
        self._reveal = redis.register_script(scripts.REVEAL)
        self._fail = redis.register_script(scripts.FAIL)

    @staticmethod
    def _key(secret_id: str) -> str:
        return KEY_PREFIX + secret_id

    async def create(
        self,
        payload: bytes,
        ttl_seconds: int,
        verifier: bytes | None = None,
    ) -> str:
        """Store a secret for `ttl_seconds` under a fresh server-made id and return the id."""
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be >= 1")
        if verifier is not None and not verifier:
            raise ValueError("verifier must be non-empty or None")
        for _ in range(_ID_RETRIES):
            secret_id = new_secret_id()
            created: Any = await self._create(
                keys=[self._key(secret_id)], args=[payload, verifier or b"", ttl_seconds]
            )
            if created == 1:
                return secret_id
        raise RuntimeError("could not allocate a free secret id")

    async def peek_verifier(self, secret_id: str) -> bytes | None:
        """The stored verifier: None if the secret is gone, empty if it has no password."""
        stored: Any = await self._peek(keys=[self._key(secret_id)])
        return None if stored is None else bytes(stored)

    async def open(
        self,
        secret_id: str,
        verifier: bytes | None = None,
        *,
        bind: Callable[[bytes, bytes], bytes] | None = None,
    ) -> OpenResult:
        """Deliver and delete a secret, or say why not.

        `verifier` is what the caller computed from the password it received. It is compared
        here, in Python, in constant time. With `bind`, the stored value is a keyed form of the
        verifier: `bind(stored, verifier)` gives the value the stored one would have if the
        verifier is right, and that is what gets compared.
        """
        key = self._key(secret_id)
        if verifier is None:
            return await self._deliver(key, proven=False)
        stored: Any = await self._peek(keys=[key])
        if stored is None:
            return NotFound()
        if not stored:  # public secret: the extra verifier is irrelevant
            return await self._deliver(key, proven=False)
        expected = bytes(stored)
        if hmac.compare_digest(expected, bind(expected, verifier) if bind else verifier):
            return await self._deliver(key, proven=True)
        left: Any = await self._fail(keys=[key], args=[self._max_attempts])
        return NotFound() if left == -1 else WrongPassword(attempts_left=int(left))

    async def _deliver(self, key: str, *, proven: bool) -> OpenResult:
        out: Any = await self._reveal(keys=[key], args=["1" if proven else "0"])
        if out is None:
            return NotFound()
        if out == 0:
            return PasswordRequired()
        return Revealed(payload=bytes(out))
