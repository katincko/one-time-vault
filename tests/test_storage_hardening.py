"""Guards on how the storage layer is built, not on what it returns."""

import base64
import hmac
import inspect
import re
import secrets
from typing import Any

import pytest
from redis.asyncio import Redis

from one_time_vault import (
    NotFound,
    Revealed,
    SecretStorage,
    WrongPassword,
)
from one_time_vault import storage as storage_module
from one_time_vault.storage import ID_LENGTH, new_secret_id

CANDIDATE = b"CANDIDATE-verifier-7c1e9a"
ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")


async def test_verifier_is_compared_with_hmac_compare_digest(
    redis: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        calls.append((bytes(a), bytes(b)))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    store = SecretStorage(redis)
    sid = await store.create(b"c", 60, verifier=CANDIDATE)
    assert await store.open(sid, b"wrong") == WrongPassword(4)
    assert await store.open(sid, CANDIDATE) == Revealed(b"c")
    assert calls == [(CANDIDATE, b"wrong"), (CANDIDATE, CANDIDATE)]


async def _lua_args_during(redis: Redis, monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """Start recording every argument that goes to the server in script commands."""
    seen: list[bytes] = []
    real: Any = redis.execute_command

    async def spy(*args: Any, **kwargs: Any) -> Any:
        if str(args[0]).upper() in {"EVAL", "EVALSHA", "SCRIPT"}:
            seen.extend(a if isinstance(a, bytes) else str(a).encode() for a in args)
        return await real(*args, **kwargs)

    monkeypatch.setattr(redis, "execute_command", spy)
    return seen


async def test_no_script_argument_contains_the_candidate_verifier(
    redis: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SecretStorage(redis)
    wrong_id = await store.create(b"c", 60, verifier=b"stored-verifier-bytes")
    right_id = await store.create(b"c", 60, verifier=CANDIDATE)
    await redis.script_flush()  # also covers the SCRIPT LOAD path after NOSCRIPT
    seen = await _lua_args_during(redis, monkeypatch)
    assert await store.open(wrong_id, CANDIDATE) == WrongPassword(4)
    assert await store.open(right_id, CANDIDATE) == Revealed(b"c")
    assert len(seen) >= 6  # the recorder is alive: EVALSHA, SCRIPT LOAD and their arguments
    assert not [a for a in seen if CANDIDATE in a], "candidate verifier reached the server"


async def test_secret_ids_are_made_by_the_server_from_128_random_bits(
    redis: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert "secret_id" not in inspect.signature(SecretStorage.create).parameters
    requested: list[int] = []
    real = secrets.token_bytes

    def spy(n: int | None = None) -> bytes:
        requested.append(n or 0)
        return real(n)

    monkeypatch.setattr(secrets, "token_bytes", spy)
    store = SecretStorage(redis)
    sid = await store.create(b"c", 60)
    assert requested == [16]
    assert ID_RE.match(sid) and len(sid) == ID_LENGTH
    assert len(base64.urlsafe_b64decode(sid + "==")) == 16
    assert await redis.exists(f"ovv:s:{sid}") == 1


def test_ids_do_not_repeat() -> None:
    assert len({new_secret_id() for _ in range(5000)}) == 5000


async def test_create_retries_on_an_id_collision_and_never_overwrites(
    redis: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SecretStorage(redis)
    first = await store.create(b"first", 60)
    ids = iter([first, first, "B" * 22])
    monkeypatch.setattr(storage_module, "new_secret_id", lambda: next(ids))
    second = await store.create(b"second", 60)
    assert second == "B" * 22
    assert await store.open(first) == Revealed(b"first")
    assert await store.open(second) == Revealed(b"second")


async def test_create_gives_up_when_every_id_is_taken(
    redis: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SecretStorage(redis)
    taken = await store.create(b"first", 60)
    monkeypatch.setattr(storage_module, "new_secret_id", lambda: taken)
    with pytest.raises(RuntimeError):
        await store.create(b"second", 60)
    assert await store.open(taken) == Revealed(b"first")
    assert await store.open(taken) == NotFound()
