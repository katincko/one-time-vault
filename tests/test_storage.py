import asyncio

import pytest
from redis.asyncio import Redis

from one_time_vault import (
    NotFound,
    PasswordRequired,
    Revealed,
    SecretStorage,
    WrongPassword,
)

V = b"verifier-bytes-0123456789abcdef"


def key(secret_id: str) -> str:
    return f"ovv:s:{secret_id}"


async def test_create_then_open_delivers_payload(redis: Redis) -> None:
    store = SecretStorage(redis)
    sid = await store.create(b"cipher", 60)
    assert await store.open(sid) == Revealed(b"cipher")


async def test_second_read_fails(redis: Redis) -> None:
    store = SecretStorage(redis)
    sid = await store.create(b"cipher", 60)
    await store.open(sid)
    assert await store.open(sid) == NotFound()
    assert await redis.exists(key(sid)) == 0


async def test_ttl_is_set_and_secret_vanishes_in_real_redis(redis: Redis) -> None:
    store = SecretStorage(redis)
    sid = await store.create(b"cipher", 1)
    assert 0 < await redis.pttl(key(sid)) <= 1000
    for _ in range(40):  # up to ~4s for a 1s TTL
        if await redis.exists(key(sid)) == 0:
            break
        await asyncio.sleep(0.1)
    assert await redis.exists(key(sid)) == 0
    assert await store.open(sid) == NotFound()


async def test_missing_read_and_expired_are_indistinguishable(redis: Redis) -> None:
    store = SecretStorage(redis)
    read = await store.create(b"c", 60)
    await store.open(read)
    expired = await store.create(b"c", 1)
    await asyncio.sleep(1.5)
    for secret_id in ("never", read, expired):
        assert await store.open(secret_id) == NotFound()
        assert await store.open(secret_id, V) == NotFound()


async def test_protected_secret_needs_the_verifier(redis: Redis) -> None:
    store = SecretStorage(redis)
    sid = await store.create(b"cipher", 60, verifier=V)
    assert await store.open(sid) == PasswordRequired()
    assert await redis.exists(key(sid)) == 1  # untouched, not counted
    assert await redis.hget(key(sid), "attempts") == b"0"
    assert await store.open(sid, V) == Revealed(b"cipher")
    assert await store.open(sid, V) == NotFound()


async def test_five_wrong_passwords_destroy_the_secret(redis: Redis) -> None:
    store = SecretStorage(redis)
    sid = await store.create(b"cipher", 60, verifier=V)
    results = [await store.open(sid, b"wrong") for _ in range(5)]
    assert results == [WrongPassword(n) for n in (4, 3, 2, 1, 0)]
    assert await redis.exists(key(sid)) == 0
    assert await store.open(sid, V) == NotFound()


async def test_right_password_after_wrong_ones_still_works(redis: Redis) -> None:
    store = SecretStorage(redis)
    sid = await store.create(b"cipher", 60, verifier=V)
    assert await store.open(sid, b"wrong") == WrongPassword(4)
    assert await store.open(sid, V) == Revealed(b"cipher")


async def test_public_secret_ignores_a_verifier(redis: Redis) -> None:
    store = SecretStorage(redis)
    sid = await store.create(b"cipher", 60)
    assert await store.open(sid, b"whatever") == Revealed(b"cipher")


async def test_scripts_survive_script_flush(redis: Redis) -> None:
    store = SecretStorage(redis)
    sid = await store.create(b"c", 60, verifier=V)
    await redis.script_flush()  # server forgets every script: NOSCRIPT on the next EVALSHA
    assert await store.open(sid, b"wrong") == WrongPassword(4)
    assert await store.open(sid, V) == Revealed(b"c")
    await redis.script_flush()
    assert await store.create(b"c", 60)


async def test_invalid_arguments_are_rejected(redis: Redis) -> None:
    store = SecretStorage(redis)
    for ttl in (0, -1):
        with pytest.raises(ValueError):
            await store.create(b"c", ttl)
    with pytest.raises(ValueError):
        await store.create(b"c", 60, verifier=b"")
