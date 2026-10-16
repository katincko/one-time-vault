"""Spec test 7: the access password, through the HTTP API against a real Redis/Valkey."""

import asyncio
import hashlib
import hmac
import os
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from conftest import KEY_V1, KEY_V2, SERVER_KEYS
from one_time_vault.app import create_app
from one_time_vault.keyring import Keyring
from one_time_vault.storage import new_secret_id
from test_api import _shape, b64, body, secret_count

VERIFIER = bytes(range(32))
RIGHT = b64(VERIFIER)
WRONG = b64(bytes(32))
ITER = 600_000
ONLY_V1 = f"1:{SERVER_KEYS.split('1:')[1]}"
ONLY_V2 = SERVER_KEYS.split(",")[0]


def sealed(key: bytes, version: int, verifier: bytes) -> bytes:
    """What the server must store: version, iterations, HMAC of the verifier under the key."""
    header = bytes([version]) + ITER.to_bytes(4, "big")
    return header + hmac.new(key, verifier, hashlib.sha256).digest()


def protected(**over: Any) -> dict[str, Any]:
    return body(**{"password_verifier": RIGHT, "iterations": ITER, **over})


def app_client(redis: Redis, keys: str = SERVER_KEYS) -> httpx.AsyncClient:
    app = create_app(redis, Keyring.parse(keys), create_limit=10_000)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://vault.test")


@pytest_asyncio.fixture
async def client(redis: Redis) -> AsyncIterator[httpx.AsyncClient]:
    async with app_client(redis) as c:
        yield c


async def make(client: httpx.AsyncClient, **over: Any) -> str:
    res = await client.post("/api/secrets", json=protected(**over))
    assert res.status_code == 201, res.text
    return str(res.json()["id"])


async def reveal(client: httpx.AsyncClient, sid: str, verifier: str | None) -> httpx.Response:
    return await client.post(
        f"/api/secrets/{sid}/reveal", json=None if verifier is None else {"verifier": verifier}
    )


async def test_the_server_stores_a_keyed_hash_never_the_verifier(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    sid = await make(client)
    stored = await redis.hgetall(f"ovv:s:{sid}")
    assert stored[b"verifier"] == sealed(KEY_V2, 2, VERIFIER)
    everything = b"".join(v if isinstance(v, bytes) else v.encode() for v in stored.values())
    assert VERIFIER not in everything and RIGHT.encode() not in everything


async def test_a_protected_secret_asks_for_the_password_and_keeps_every_attempt(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    sid = await make(client)
    res = await reveal(client, sid, None)
    assert (res.status_code, res.json()) == (
        403,
        {"error": "password_required", "iterations": ITER},
    )
    assert await redis.hget(f"ovv:s:{sid}", "attempts") == b"0"  # asking is not an attempt
    assert (await reveal(client, sid, RIGHT)).status_code == 200


async def test_the_right_password_delivers_once(client: httpx.AsyncClient) -> None:
    sent = protected()
    sid = str((await client.post("/api/secrets", json=sent)).json()["id"])
    ok = await reveal(client, sid, RIGHT)
    assert ok.status_code == 200
    assert ok.json() == {"iv": sent["iv"], "ciphertext": sent["ciphertext"]}
    assert (await reveal(client, sid, RIGHT)).status_code == 404


async def test_five_wrong_passwords_destroy_the_secret(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    sid = await make(client)
    wrong = [await reveal(client, sid, WRONG) for _ in range(5)]
    assert [r.status_code for r in wrong] == [403] * 5
    assert [r.json() for r in wrong] == [
        {"error": "wrong_password", "attempts_left": n} for n in (4, 3, 2, 1, 0)
    ]
    assert await redis.exists(f"ovv:s:{sid}") == 0
    assert (await reveal(client, sid, RIGHT)).status_code == 404  # even the right one, now


async def test_simultaneous_wrong_passwords_are_counted_exactly_to_the_limit(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    sid = await make(client)
    res = await asyncio.gather(*(reveal(client, sid, WRONG) for _ in range(40)))
    assert sorted(r.status_code for r in res) == [403] * 5 + [404] * 35
    left = sorted(r.json()["attempts_left"] for r in res if r.status_code == 403)
    assert left == [0, 1, 2, 3, 4]
    assert await redis.exists(f"ovv:s:{sid}") == 0


async def test_simultaneous_right_and_wrong_passwords_deliver_at_most_once(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    for _ in range(5):
        sid = await make(client)
        verifiers = [RIGHT if i % 4 == 0 else WRONG for i in range(40)]
        res = await asyncio.gather(*(reveal(client, sid, v) for v in verifiers))
        codes = [r.status_code for r in res]
        assert codes.count(200) <= 1
        assert codes.count(403) <= 5
        assert set(codes) <= {200, 403, 404}
        assert await redis.exists(f"ovv:s:{sid}") == 0  # delivered or destroyed, never left over


async def test_a_gone_secret_gets_the_one_404_with_or_without_a_verifier(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    read = await make(client)
    await reveal(client, read, RIGHT)
    expired = await make(client)
    await redis.pexpire(f"ovv:s:{expired}", 100)
    await asyncio.sleep(0.4)
    baseline = await _shape(await reveal(client, new_secret_id(), None))
    assert baseline[0] == 404
    ids = {"read": read, "expired": expired, "never": new_secret_id(), "malformed": "abc"}
    odd = {}
    for name, sid in ids.items():
        for label, verifier in (("no verifier", None), ("wrong", WRONG), ("right", RIGHT)):
            shape = await _shape(await reveal(client, sid, verifier))
            if shape != baseline:
                odd[f"{name}/{label}"] = shape
    assert odd == {}


async def test_a_public_secret_ignores_a_verifier(client: httpx.AsyncClient) -> None:
    res = await client.post("/api/secrets", json=body())
    assert (await reveal(client, res.json()["id"], WRONG)).status_code == 200


async def test_a_malformed_verifier_is_refused_and_not_counted(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    sid = await make(client)
    bad = [b64(os.urandom(31)), b64(os.urandom(33)), "", RIGHT + "==", "!" * 43, 7, None]
    for v in bad:
        res = await client.post(f"/api/secrets/{sid}/reveal", json={"verifier": v})
        assert res.status_code == 422, v
    extra = await client.post(f"/api/secrets/{sid}/reveal", json={"verifier": RIGHT, "x": 1})
    assert extra.status_code == 422
    assert await redis.hget(f"ovv:s:{sid}", "attempts") == b"0"
    assert (await reveal(client, sid, RIGHT)).status_code == 200


PASSWORD_REFUSALS: dict[str, dict[str, Any]] = {
    "verifier without iterations": body(password_verifier=RIGHT),
    "iterations without verifier": body(iterations=ITER),
    "iterations one below the floor": protected(iterations=ITER - 1),
    "iterations one above the ceiling": protected(iterations=1_000_001),
    "iterations zero": protected(iterations=0),
    "iterations as text": protected(iterations="600000"),
    "iterations as a float": protected(iterations=600000.5),
    "iterations true": protected(iterations=True),
    "verifier 31 bytes": protected(password_verifier=b64(os.urandom(31))),
    "verifier 33 bytes": protected(password_verifier=b64(os.urandom(33))),
    "verifier empty": protected(password_verifier=""),
    "verifier with padding": protected(password_verifier=RIGHT + "=="),
    "verifier not base64url": protected(password_verifier="*" * 43),
    "verifier not a string": protected(password_verifier=5),
}


@pytest.mark.parametrize("case", list(PASSWORD_REFUSALS))
async def test_every_password_refusal_is_an_error_and_stores_nothing(
    client: httpx.AsyncClient, redis: Redis, case: str
) -> None:
    res = await client.post("/api/secrets", json=PASSWORD_REFUSALS[case])
    assert res.status_code == 422, (case, res.text[:200])
    assert await secret_count(redis) == 0


@pytest.mark.parametrize("iterations", [ITER, 800_000, 1_000_000])
async def test_iterations_inside_the_interval_are_kept_for_the_opener(
    client: httpx.AsyncClient, iterations: int
) -> None:
    sid = await make(client, iterations=iterations)
    assert (await reveal(client, sid, None)).json()["iterations"] == iterations


async def test_a_key_rotation_keeps_old_secrets_openable(redis: Redis) -> None:
    async with app_client(redis, ONLY_V1) as before:
        sid = await make(before)
    async with app_client(redis, SERVER_KEYS) as after:  # 2 is current, 1 is kept
        assert (await reveal(after, sid, WRONG)).json()["attempts_left"] == 4
        assert (await reveal(after, sid, RIGHT)).status_code == 200
        fresh = await make(after)
    stored = await redis.hget(f"ovv:s:{fresh}", "verifier")
    assert stored == sealed(KEY_V2, 2, VERIFIER)  # new secrets use the new key


async def test_a_dropped_key_is_a_server_error_that_does_not_burn_attempts(
    redis: Redis,
) -> None:
    async with app_client(redis, ONLY_V1) as before:
        sid = await make(before)
    async with app_client(redis, ONLY_V2) as after:
        assert (await reveal(after, sid, RIGHT)).status_code == 500
    assert await redis.hget(f"ovv:s:{sid}", "attempts") == b"0"
    assert await redis.exists(f"ovv:s:{sid}") == 1


async def test_the_candidate_is_compared_in_constant_time_in_python(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    sid = await make(client)
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        calls.append((bytes(a), bytes(b)))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    await reveal(client, sid, WRONG)
    await reveal(client, sid, RIGHT)
    right = sealed(KEY_V2, 2, VERIFIER)
    assert calls == [(right, sealed(KEY_V2, 2, bytes(32))), (right, right)]
    assert KEY_V1 != KEY_V2
