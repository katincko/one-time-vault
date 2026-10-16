"""A deliberately broken storage: check-then-act in separate commands, the bug Lua prevents.

Only the race harnesses use it, to prove they would catch the bug.
"""

from redis.asyncio import Redis

from one_time_vault import (
    MAX_ATTEMPTS,
    NotFound,
    OpenResult,
    PasswordRequired,
    Revealed,
    SecretStorage,
    WrongPassword,
)


class NaiveStorage(SecretStorage):
    def __init__(self, redis: Redis) -> None:
        super().__init__(redis)
        self._r = redis

    async def open(self, secret_id: str, verifier: bytes | None = None) -> OpenResult:
        key = self._key(secret_id)
        payload, stored, attempts = await self._r.hmget(key, ["payload", "verifier", "attempts"])
        if payload is None:
            return NotFound()
        if stored is not None and verifier != stored:
            if verifier is None:
                return PasswordRequired()
            used = int(attempts or 0) + 1
            await self._r.hset(key, "attempts", used)  # lost updates under concurrency
            if used >= MAX_ATTEMPTS:
                await self._r.delete(key)
            return WrongPassword(MAX_ATTEMPTS - used)
        await self._r.delete(key)
        assert isinstance(payload, bytes)
        return Revealed(payload)
