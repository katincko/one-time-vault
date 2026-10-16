"""Concurrency proof inside one process: 50 simultaneous readers, mixed right and wrong passwords.

The same harness also runs against a deliberately naive storage (separate read and delete,
read-then-write counter) and must catch it. That keeps the negative proof alive in the suite.
"""

import asyncio

from redis.asyncio import Redis

from naive_storage import NaiveStorage
from one_time_vault import Revealed, SecretStorage, WrongPassword
from race_common import (
    READERS,
    ROUNDS,
    SCENARIOS,
    Stats,
    V,
    candidates,
    check_expectations,
    violations,
)


async def _round(
    redis: Redis, store: SecretStorage, *, protected: bool, right_share: float
) -> Stats:
    await redis.flushall()
    sid = await store.create(b"cipher", 60, verifier=V if protected else None)
    cands = candidates(READERS, protected=protected, right_share=right_share)
    results = await asyncio.gather(*(store.open(sid, c) for c in cands))
    key = f"ovv:s:{sid}"
    key_left = await redis.exists(key) == 1
    in_key = int(await redis.hget(key, "attempts") or 0) if key_left else 0
    return Stats(
        delivered=sum(isinstance(r, Revealed) for r in results),
        wrong_replies=sum(isinstance(r, WrongPassword) for r in results),
        key_left=key_left,
        attempts_in_key=in_key,
    )


async def test_at_most_one_delivery_and_counter_capped(redis: Redis) -> None:
    store = SecretStorage(redis)
    for _, protected, share in SCENARIOS:
        for _ in range(ROUNDS):
            stats = await _round(redis, store, protected=protected, right_share=share)
            check_expectations(stats, protected=protected, right_share=share)


async def test_race_harness_catches_a_non_atomic_storage(redis: Redis) -> None:
    naive = NaiveStorage(redis)
    seen: set[str] = set()
    for _, protected, share in SCENARIOS:
        for _ in range(ROUNDS):
            stats = await _round(redis, naive, protected=protected, right_share=share)
            seen.update(violations(stats))
    assert any("deliveries" in v for v in seen), seen
    assert any("counted attempts" in v for v in seen), seen
