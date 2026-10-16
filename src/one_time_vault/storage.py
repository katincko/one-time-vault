"""Redis/Valkey storage for one-time secrets.

Missing, already read and expired secrets are the same thing here: `NotFound`.
"""

import hmac
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from one_time_vault import scripts

MAX_ATTEMPTS = 5
KEY_PREFIX = "ovv:s:"


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
        secret_id: str,
        payload: bytes,
        ttl_seconds: int,
        verifier: bytes | None = None,
    ) -> bool:
        """Store a secret for `ttl_seconds`. False if the id is taken (nothing overwritten)."""
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be >= 1")
        if verifier is not None and not verifier:
            raise ValueError("verifier must be non-empty or None")
        created: Any = await self._create(
            keys=[self._key(secret_id)], args=[payload, verifier or b"", ttl_seconds]
        )
        return bool(created == 1)

    async def open(self, secret_id: str, verifier: bytes | None = None) -> OpenResult:
        """Deliver and delete a secret, or say why not.

        `verifier` is what the caller computed from the password it received. It is compared
        here, in Python, in constant time.
        """
        key = self._key(secret_id)
        if verifier is None:
            return await self._deliver(key, proven=False)
        stored: Any = await self._peek(keys=[key])
        if stored is None:
            return NotFound()
        if not stored:  # public secret: the extra verifier is irrelevant
            return await self._deliver(key, proven=False)
        if hmac.compare_digest(bytes(stored), verifier):
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
