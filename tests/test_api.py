"""The HTTP API against a real Redis/Valkey. Spec tests 2, 4 (without a browser), 8, 9 and 12."""

import asyncio
import base64
import os
import re
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from one_time_vault.app import MAX_CIPHERTEXT_BYTES, create_app
from one_time_vault.storage import new_secret_id

ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def body(**over: Any) -> dict[str, Any]:
    """A valid create request: one 256-byte block plus the 16-byte GCM tag."""
    valid = {"iv": b64(os.urandom(12)), "ciphertext": b64(os.urandom(256 + 16)), "expires_in": "1h"}
    return {**valid, **over}


@pytest_asyncio.fixture
async def client(redis: Redis) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(redis))
    async with httpx.AsyncClient(transport=transport, base_url="http://vault.test") as c:
        yield c


async def create(client: httpx.AsyncClient, **over: Any) -> tuple[str, dict[str, Any]]:
    payload = body(**over)
    res = await client.post("/api/secrets", json=payload)
    assert res.status_code == 201, res.text
    return str(res.json()["id"]), payload


# Test 2: single read


async def test_create_then_reveal_once_then_404(client: httpx.AsyncClient, redis: Redis) -> None:
    secret_id, sent = await create(client)
    assert ID_RE.match(secret_id)
    first = await client.post(f"/api/secrets/{secret_id}/reveal")
    assert first.status_code == 200
    assert first.json() == {"iv": sent["iv"], "ciphertext": sent["ciphertext"]}
    second = await client.post(f"/api/secrets/{secret_id}/reveal")
    assert second.status_code == 404
    assert await redis.exists(f"ovv:s:{secret_id}") == 0


async def test_concurrent_reveals_deliver_once(client: httpx.AsyncClient) -> None:
    secret_id, _ = await create(client)
    results = await asyncio.gather(
        *(client.post(f"/api/secrets/{secret_id}/reveal") for _ in range(30))
    )
    assert sorted(r.status_code for r in results) == [200] + [404] * 29


async def test_the_server_picks_the_id(client: httpx.AsyncClient) -> None:
    res = await client.post("/api/secrets", json=body(id="AAAAAAAAAAAAAAAAAAAAAA"))
    assert res.status_code == 422  # a caller-made id is an unknown field
    ids = {(await create(client))[0] for _ in range(5)}
    assert len(ids) == 5


# Test 8: lifetimes


@pytest.mark.parametrize(("name", "seconds"), [("1h", 3600), ("1d", 86400), ("7d", 604800)])
async def test_expiry_names_become_seconds(
    client: httpx.AsyncClient, redis: Redis, name: str, seconds: int
) -> None:
    secret_id, _ = await create(client, expires_in=name)
    ttl = await redis.ttl(f"ovv:s:{secret_id}")
    assert seconds - 5 <= ttl <= seconds


# Test 12: one 404


async def _shape(res: httpx.Response) -> tuple[int, list[tuple[str, str]], bytes]:
    headers = sorted((k, v) for k, v in res.headers.items() if k != "date")
    return res.status_code, headers, res.content


async def test_404_is_byte_identical_for_missing_read_expired_and_malformed(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    read_id, _ = await create(client)
    await client.post(f"/api/secrets/{read_id}/reveal")
    expired_id, _ = await create(client)
    await redis.pexpire(f"ovv:s:{expired_id}", 150)  # Redis itself drops it: a real expiry
    live_id, _ = await create(client)
    await asyncio.sleep(0.5)
    assert await redis.exists(f"ovv:s:{expired_id}") == 0
    shapes = {
        name: await _shape(await client.post(f"/api/secrets/{sid}/reveal"))
        for name, sid in {
            "never existed": new_secret_id(),
            "already read": read_id,
            "expired": expired_id,
            "too short": "abc",
            "too long": "A" * 200,
            "wrong chars": "!" * 22,
        }.items()
    }
    assert shapes["never existed"][0] == 404
    assert {name: s for name, s in shapes.items() if s != shapes["never existed"]} == {}
    assert (await client.post(f"/api/secrets/{live_id}/reveal")).status_code == 200


# Test 9: validation


def _flip_last_char(text: str) -> str:
    """Same bytes once decoded by a lenient decoder, but not the canonical text."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return text[:-1] + alphabet[(alphabet.index(text[-1]) + 1) % 64]


def _cipher(n_bytes: int) -> str:
    return b64(os.urandom(n_bytes))


VALID_CT = b64(bytes(272))
BAD_REQUESTS: dict[str, dict[str, Any]] = {
    "expiry outside the list": body(expires_in="2h"),
    "expiry in other case": body(expires_in="1H"),
    "expiry as seconds": body(expires_in=3600),
    "expiry empty": body(expires_in=""),
    "iv 11 bytes": body(iv=b64(os.urandom(11))),
    "iv 13 bytes": body(iv=b64(os.urandom(13))),
    "iv empty": body(iv=""),
    "iv with padding": body(iv=b64(os.urandom(12)) + "=="),
    "iv not base64url": body(iv="!" * 16),
    "iv standard alphabet": body(iv="+/" * 8),
    "iv not a string": body(iv=12),
    "ciphertext empty": body(ciphertext=""),
    "ciphertext shorter than the tag": body(ciphertext=_cipher(15)),
    "ciphertext with no block": body(ciphertext=_cipher(16)),
    "ciphertext one byte short of a block": body(ciphertext=_cipher(16 + 255)),
    "ciphertext one byte over a block": body(ciphertext=_cipher(16 + 257)),
    "ciphertext over the limit": body(ciphertext=_cipher(MAX_CIPHERTEXT_BYTES + 256)),
    "ciphertext not base64url": body(ciphertext="*" * 364),
    "ciphertext not canonical": body(ciphertext=_flip_last_char(VALID_CT)),
}


@pytest.mark.parametrize("case", list(BAD_REQUESTS))
async def test_every_refusal_is_an_error_and_stores_nothing(
    client: httpx.AsyncClient, redis: Redis, case: str
) -> None:
    res = await client.post("/api/secrets", json=BAD_REQUESTS[case])
    assert res.status_code == 422, (case, res.text[:200])
    assert await redis.dbsize() == 0


@pytest.mark.parametrize("missing", ["iv", "ciphertext", "expires_in"])
async def test_missing_fields_are_refused(
    client: httpx.AsyncClient, redis: Redis, missing: str
) -> None:
    payload = body()
    del payload[missing]
    assert (await client.post("/api/secrets", json=payload)).status_code == 422
    assert await redis.dbsize() == 0


@pytest.mark.parametrize("blocks", [1, 2, 41])
async def test_valid_sizes_up_to_the_limit_are_accepted(
    client: httpx.AsyncClient, blocks: int
) -> None:
    ct = b64(os.urandom(256 * blocks + 16))
    assert len(ct) <= 16 * 1024 - 200  # the largest request also fits the body limit
    await create(client, ciphertext=ct)


async def test_the_largest_ciphertext_is_exactly_the_10kb_text_limit_padded(
    client: httpx.AsyncClient,
) -> None:
    assert MAX_CIPHERTEXT_BYTES == 10 * 1024 + 256 + 16


# Body limit


async def test_a_body_over_the_limit_is_413_by_content_length(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    res = await client.post("/api/secrets", content=b"x" * 200_000)
    assert res.status_code == 413
    assert await redis.dbsize() == 0


async def test_a_streamed_body_over_the_limit_is_413_without_content_length(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(50):
            yield b"x" * 10_000

    req = client.build_request("POST", "/api/secrets", content=chunks())
    assert "content-length" not in req.headers
    res = await client.send(req)
    assert res.status_code == 413
    assert await redis.dbsize() == 0


# Test 4 (API half): opening a link consumes nothing

PREVIEW_AGENTS = [
    "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "WhatsApp/2.23.20.0 A",
    "Twitterbot/1.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
    "TelegramBot (like TwitterBot)",
    "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/605.1.15 (Messages link preview)",
    "curl/8.5.0",
]


@pytest.mark.parametrize("agent", PREVIEW_AGENTS)
async def test_get_and_head_with_preview_agents_consume_nothing(
    client: httpx.AsyncClient, redis: Redis, agent: str
) -> None:
    secret_id, sent = await create(client)
    for method in ("GET", "HEAD"):
        res = await client.request(method, f"/s/{secret_id}", headers={"user-agent": agent})
        assert res.status_code == 200, (method, res.status_code)
        assert res.headers["content-type"].startswith("text/html")
    assert await redis.exists(f"ovv:s:{secret_id}") == 1
    assert await redis.hget(f"ovv:s:{secret_id}", "attempts") == b"0"
    reveal = await client.post(f"/api/secrets/{secret_id}/reveal")
    assert reveal.json()["ciphertext"] == sent["ciphertext"]


async def test_the_open_page_is_the_same_for_every_id(
    client: httpx.AsyncClient,
) -> None:
    real, _ = await create(client)
    pages = {(await client.get(f"/s/{sid}")).content for sid in (real, new_secret_id(), "nonsense")}
    assert len(pages) == 1  # the page cannot tell a live id from a dead one


async def test_pages_and_scripts_are_served(client: httpx.AsyncClient) -> None:
    assert (await client.get("/")).status_code == 200
    js = await client.get("/static/vault-crypto.js")
    assert js.status_code == 200
    assert "javascript" in js.headers["content-type"]
