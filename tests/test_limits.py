"""Spec test 10: the per-IP creation limit (429) and the size limit (413)."""

import asyncio
import secrets
from collections.abc import AsyncIterator, Callable, Iterator

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from conftest import SERVER_KEYS, LiveServer, run_server
from one_time_vault.app import create_app
from one_time_vault.keyring import Keyring
from one_time_vault.ratelimit import client_ip
from test_api import body

LIMIT = 3
PEER = "10.0.0.9"  # the proxy, as the socket sees it

MakeClient = Callable[..., httpx.AsyncClient]


@pytest_asyncio.fixture
async def make_client(redis: Redis) -> AsyncIterator[MakeClient]:
    opened: list[httpx.AsyncClient] = []

    def make(*, hops: int = 0, peer: str = PEER, limit: int = LIMIT) -> httpx.AsyncClient:
        app = create_app(
            redis,
            Keyring.parse(SERVER_KEYS),
            create_limit=limit,
            create_window_seconds=600,
            trusted_hops=hops,
        )
        transport = httpx.ASGITransport(app=app, client=(peer, 5000))
        c = httpx.AsyncClient(transport=transport, base_url="http://vault.test")
        opened.append(c)
        return c

    yield make
    for c in opened:
        await c.aclose()


async def statuses(client: httpx.AsyncClient, n: int, **headers: str) -> list[int]:
    return [(await client.post("/api/secrets", json=body(), headers=headers)).status_code
            for _ in range(n)]  # fmt: skip


async def test_the_creation_after_the_limit_is_429_with_retry_after(
    make_client: MakeClient,
) -> None:
    client = make_client()
    assert await statuses(client, LIMIT + 2) == [201] * LIMIT + [429, 429]
    refused = await client.post("/api/secrets", json=body())
    assert refused.json() == {"detail": "too many requests"}
    assert 1 <= int(refused.headers["retry-after"]) <= 600


async def test_reading_is_not_limited(make_client: MakeClient) -> None:
    client = make_client(limit=1)
    made = await client.post("/api/secrets", json=body())
    assert made.status_code == 201
    assert (await client.post("/api/secrets", json=body())).status_code == 429
    assert (await client.get(f"/s/{made.json()['id']}")).status_code == 200
    assert (await client.post(f"/api/secrets/{made.json()['id']}/reveal")).status_code == 200


async def test_each_ip_has_its_own_count(make_client: MakeClient) -> None:
    a, b = make_client(peer="198.51.100.1"), make_client(peer="198.51.100.2")
    assert await statuses(a, LIMIT + 1) == [201] * LIMIT + [429]
    assert await statuses(b, 1) == [201]


async def test_a_forged_forwarded_header_does_not_pick_the_bucket(
    make_client: MakeClient,
) -> None:
    """One trusted proxy: it appends the real client, so the rightmost entry is the truth."""
    client = make_client(hops=1)
    real = "203.0.113.5"
    forged = [
        await statuses(client, 1, **{"X-Forwarded-For": f"198.51.100.{i}, {real}"})
        for i in range(LIMIT + 2)
    ]
    assert [s[0] for s in forged] == [201] * LIMIT + [429, 429]
    # a different real client behind the same proxy is not affected
    assert await statuses(client, 1, **{"X-Forwarded-For": "198.51.100.1, 203.0.113.6"}) == [201]


async def test_without_trusted_hops_the_header_is_ignored(make_client: MakeClient) -> None:
    client = make_client(hops=0)
    results = [
        (await statuses(client, 1, **{"X-Forwarded-For": f"203.0.113.{i}"}))[0]
        for i in range(LIMIT + 2)
    ]
    assert results == [201] * LIMIT + [429, 429]


async def test_a_missing_or_short_header_falls_back_to_the_peer(make_client: MakeClient) -> None:
    client = make_client(hops=2)
    one_hop = {"X-Forwarded-For": "203.0.113.5"}  # fewer entries than trusted proxies
    results = await statuses(client, 1, **one_hop) + await statuses(client, LIMIT)
    assert results.count(429) == 1  # both kinds landed in the peer's bucket


async def test_two_trusted_hops_take_the_second_entry_from_the_right(
    make_client: MakeClient,
) -> None:
    client = make_client(hops=2)
    header = {"X-Forwarded-For": "1.1.1.1, 203.0.113.5, 192.0.2.1"}
    assert await statuses(client, LIMIT + 1, **header) == [201] * LIMIT + [429]


async def test_the_count_is_one_atomic_step_under_concurrency(
    make_client: MakeClient, redis: Redis
) -> None:
    client = make_client(limit=10)
    results = await asyncio.gather(*(statuses(client, 1) for _ in range(60)))
    flat = sorted(s[0] for s in results)
    assert flat == [201] * 10 + [429] * 50
    (counter,) = [k async for k in redis.scan_iter("ovv:rl:*")]
    assert await redis.get(counter) == b"60"
    assert 0 < await redis.pttl(counter) <= 600_000  # the window always ends


async def test_a_refused_body_still_counts_toward_the_limit(make_client: MakeClient) -> None:
    client = make_client(limit=2)
    too_big = [await client.post("/api/secrets", content=b"x" * 200_000) for _ in range(2)]
    assert [r.status_code for r in too_big] == [413, 413]
    assert (await client.post("/api/secrets", json=body())).status_code == 429


async def test_a_body_over_the_size_limit_is_413_and_stores_nothing(
    make_client: MakeClient, redis: Redis
) -> None:
    client = make_client()
    res = await client.post("/api/secrets", content=b"x" * 200_000)
    assert res.status_code == 413
    assert [k async for k in redis.scan_iter("ovv:s:*")] == []


@pytest.mark.parametrize(
    ("peer", "header", "hops", "bucket"),
    [
        ("198.51.100.1", None, 0, "198.51.100.1"),
        ("10.0.0.9", "7.7.7.7, 203.0.113.5", 1, "203.0.113.5"),
        ("10.0.0.9", "7.7.7.7, not-an-ip", 1, "10.0.0.9"),  # free text never becomes a key
        ("10.0.0.9", "7.7.7.7, 2001:db8:1:2:aaaa:bbbb:cccc:dddd", 1, "2001:db8:1:2::/64"),
        ("2001:db8:9:9:1:2:3:4", None, 0, "2001:db8:9:9::/64"),
    ],
)
def test_client_ip_buckets(peer: str, header: str | None, hops: int, bucket: str) -> None:
    raw = [(b"x-forwarded-for", header.encode())] if header else []
    scope = {"type": "http", "client": (peer, 1), "headers": raw}
    assert client_ip(scope, hops) == bucket


@pytest.mark.parametrize(
    ("peer", "header", "hops", "bucket"),
    [
        ("::ffff:198.51.100.7", None, 0, "198.51.100.7"),
        ("::ffff:198.51.100.8", None, 0, "198.51.100.8"),
        ("10.0.0.9", "7.7.7.7, ::ffff:203.0.113.5", 1, "203.0.113.5"),
        ("10.0.0.9", "7.7.7.7, ::FFFF:203.0.113.6", 1, "203.0.113.6"),
        ("::ffff:10.0.0.9", "7.7.7.7, ::ffff:203.0.113.5", 1, "203.0.113.5"),
        ("::ffff:c633:6407", None, 0, "198.51.100.7"),  # the hex spelling of the same address
        ("2001:db8:1:2:aaaa:bbbb:cccc:dddd", None, 0, "2001:db8:1:2::/64"),  # real IPv6 unchanged
        # a trusted header that is not an address falls back to the peer, normalized the same way
        ("::ffff:1.2.3.4", "garbage", 1, "1.2.3.4"),
        ("::ffff:1.2.3.4", "", 1, "1.2.3.4"),
        ("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "not an ip", 1, "2001:db8:1:2::/64"),
        ("10.0.0.9", "7.7.7.7, evil key", 1, "10.0.0.9"),
        ("not an address", None, 0, "unknown"),  # free text never becomes a key
    ],
)
def test_an_ipv4_mapped_in_ipv6_is_the_plain_ipv4(
    peer: str, header: str | None, hops: int, bucket: str
) -> None:
    raw = [(b"x-forwarded-for", header.encode())] if header else []
    scope = {"type": "http", "client": (peer, 1), "headers": raw}
    assert client_ip(scope, hops) == bucket


async def test_two_mapped_ipv4_addresses_have_their_own_buckets(make_client: MakeClient) -> None:
    a, b = make_client(peer="::ffff:198.51.100.1"), make_client(peer="::ffff:198.51.100.2")
    assert await statuses(a, LIMIT + 1) == [201] * LIMIT + [429]
    assert await statuses(b, 1) == [201]  # a shared ::/64 bucket would be spent already


async def test_a_mapped_ipv4_and_the_plain_one_share_a_bucket(make_client: MakeClient) -> None:
    mapped, plain = make_client(peer="::ffff:198.51.100.3"), make_client(peer="198.51.100.3")
    assert await statuses(mapped, LIMIT) == [201] * LIMIT
    assert await statuses(plain, 1) == [429]


async def test_a_mapped_ipv4_in_the_forwarded_header_has_its_own_bucket(
    make_client: MakeClient,
) -> None:
    c = make_client(hops=1)
    one, two = "::ffff:203.0.113.1", "::ffff:203.0.113.2"
    assert await statuses(c, LIMIT + 1, **{"X-Forwarded-For": one}) == [201] * LIMIT + [429]
    assert await statuses(c, 1, **{"X-Forwarded-For": two}) == [201]
    assert await statuses(c, 1, **{"X-Forwarded-For": "203.0.113.1"}) == [429]  # same as `one`


async def test_a_whole_ipv6_64_shares_one_bucket(make_client: MakeClient) -> None:
    results = []
    for i in range(LIMIT + 1):
        c = make_client(peer=f"2001:db8:1:2:{i}::{i}")  # a different address each time
        results += await statuses(c, 1)
    assert results == [201] * LIMIT + [429]


@pytest.fixture(scope="module")
def limited_server(
    server_url: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[LiveServer]:
    """The real process behind one trusted proxy, with a creation limit of 3."""
    env = {"OTV_CREATE_LIMIT": "3", "OTV_TRUSTED_HOPS": "1"}
    with run_server(server_url, tmp_path_factory.mktemp("limited") / "server.log", env) as server:
        yield server


def test_the_real_server_ignores_a_forged_header_and_answers_429_and_413(
    limited_server: LiveServer,
) -> None:
    real = f"203.0.113.{secrets.randbelow(200) + 20}"  # the proxy appends the address it saw
    sent = body()
    codes = [
        httpx.post(
            limited_server.url + "/api/secrets",
            json=sent,
            headers={"X-Forwarded-For": f"198.51.100.{i}, {real}"},
        ).status_code
        for i in range(5)
    ]
    assert codes == [201, 201, 201, 429, 429]
    other = httpx.post(
        limited_server.url + "/api/secrets",
        json=sent,
        headers={"X-Forwarded-For": f"198.51.100.1, 203.0.113.{secrets.randbelow(20)}"},
    )
    assert other.status_code == 201  # another real client is not limited
    big = httpx.post(
        limited_server.url + "/api/secrets",
        content=b"x" * 200_000,
        headers={"X-Forwarded-For": "198.51.100.1, 203.0.113.250"},
    )
    assert big.status_code == 413
