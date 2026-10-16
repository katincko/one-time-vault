"""Concurrency proof: 50 simultaneous readers, mixed right and wrong passwords.

The same harness also runs against a deliberately naive storage (separate read and delete,
read-then-write counter) and must catch it. That keeps the negative proof alive in the suite.
"""

import asyncio
import random
from dataclasses import dataclass

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

READERS = 50
ROUNDS = 15
V = b"verifier-bytes-0123456789abcdef"


class NaiveStorage(SecretStorage):
    """Same data layout, but check-then-act in separate commands: the bug Lua prevents."""

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


@dataclass
class Stats:
    delivered: int
    wrong_replies: int
    key_left: bool
    attempts_in_key: int


async def _round(
    redis: Redis, store: SecretStorage, *, protected: bool, right_share: float
) -> Stats:
    await redis.flushall()
    sid = await store.create(b"cipher", 60, verifier=V if protected else None)
    candidates: list[bytes | None] = [
        (V if random.random() < right_share else b"wrong") if protected else None
        for _ in range(READERS)
    ]
    results = await asyncio.gather(*(store.open(sid, c) for c in candidates))
    key = f"ovv:s:{sid}"
    key_left = await redis.exists(key) == 1
    in_key = int(await redis.hget(key, "attempts") or 0) if key_left else 0
    return Stats(
        delivered=sum(isinstance(r, Revealed) for r in results),
        wrong_replies=sum(isinstance(r, WrongPassword) for r in results),
        key_left=key_left,
        attempts_in_key=in_key,
    )


# (name, protected, share of readers with the right password)
SCENARIOS = [
    ("public", False, 0.0),
    ("protected, all right", True, 1.0),
    ("protected, mixed", True, 0.5),
    ("protected, mostly wrong", True, 0.02),
    ("protected, all wrong", True, 0.0),
]


def _violations(stats: Stats) -> list[str]:
    bad = []
    if stats.delivered > 1:
        bad.append(f"{stats.delivered} deliveries")
    if stats.wrong_replies > MAX_ATTEMPTS:
        bad.append(f"{stats.wrong_replies} counted attempts")
    if stats.attempts_in_key >= MAX_ATTEMPTS:
        bad.append("counter reached the limit but the key survived")
    if stats.delivered and stats.key_left:
        bad.append("delivered but still stored")
    return bad


async def test_at_most_one_delivery_and_counter_capped(redis: Redis) -> None:
    store = SecretStorage(redis)
    for name, protected, share in SCENARIOS:
        for i in range(ROUNDS):
            stats = await _round(redis, store, protected=protected, right_share=share)
            assert not _violations(stats), (name, i, stats)
            if protected and share == 0.0:
                assert stats.delivered == 0
                assert stats.wrong_replies == MAX_ATTEMPTS
                assert not stats.key_left
            if not protected or share == 1.0:
                assert stats.delivered == 1


async def test_race_harness_catches_a_non_atomic_storage(redis: Redis) -> None:
    naive = NaiveStorage(redis)
    seen: set[str] = set()
    for _, protected, share in SCENARIOS:
        for _ in range(ROUNDS):
            stats = await _round(redis, naive, protected=protected, right_share=share)
            seen.update(_violations(stats))
    assert any("deliveries" in v for v in seen), seen
    assert any("counted attempts" in v for v in seen), seen
