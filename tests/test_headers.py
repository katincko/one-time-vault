"""Spec test 11: security headers on pages and on the API, with a new nonce on every response."""

import logging
import re
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from conftest import SERVER_KEYS
from one_time_vault.app import create_app
from one_time_vault.keyring import Keyring
from one_time_vault.ratelimit import CreateLimiter
from one_time_vault.storage import SecretStorage, new_secret_id
from test_api import body

# The policy as written in the spec, with N standing for the nonce.
SPEC_CSP = (
    "default-src 'none'; script-src 'nonce-N' 'strict-dynamic'; connect-src 'self'; "
    "style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
    "object-src 'none'"
)
NONCE = re.compile(r"'nonce-([A-Za-z0-9_-]{22,})'")


@pytest_asyncio.fixture
async def client(redis: Redis) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(redis, Keyring.parse(SERVER_KEYS), create_limit=3, create_window_seconds=600)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://vault.test") as c:
        yield c


def nonce_of(res: httpx.Response) -> str:
    match = NONCE.search(res.headers["content-security-policy"])
    assert match, res.headers.get("content-security-policy")
    return match.group(1)


async def responses(client: httpx.AsyncClient) -> dict[str, httpx.Response]:
    """One response of every kind the app can give: pages, API successes and API refusals."""
    created = await client.post("/api/secrets", json=body())
    secret_id = created.json()["id"]
    return {
        "index": await client.get("/"),
        "open page": await client.get(f"/s/{secret_id}"),
        "open page HEAD": await client.head(f"/s/{secret_id}"),
        "static script": await client.get("/static/open.js"),
        "static style": await client.get("/static/style.css"),
        "create 201": created,
        "create 422": await client.post("/api/secrets", json={}),
        "create 413": await client.post("/api/secrets", content=b"x" * 200_000),
        "reveal 200": await client.post(f"/api/secrets/{secret_id}/reveal"),
        "reveal 404": await client.post(f"/api/secrets/{new_secret_id()}/reveal"),
        "unknown route 404": await client.get("/api/secrets/nope/nope"),
        "create 429": await client.post("/api/secrets", json=body()),
    }


async def test_every_response_has_the_security_headers(client: httpx.AsyncClient) -> None:
    got = await responses(client)
    assert [k for k, r in got.items() if r.status_code == 429] == ["create 429"]  # all kinds seen
    assert {r.status_code for r in got.values()} >= {200, 201, 404, 413, 422, 429}
    wrong: dict[str, dict[str, str | None]] = {}
    for name, res in got.items():
        h = res.headers
        seen = {
            "csp": NONCE.sub("'nonce-N'", h.get("content-security-policy", "")),
            "nosniff": h.get("x-content-type-options"),
            "referrer": h.get("referrer-policy"),
            "cache": h.get("cache-control"),
            "hsts": h.get("strict-transport-security"),
        }
        want = {
            "csp": SPEC_CSP,
            "nosniff": "nosniff",
            "referrer": "no-referrer",
            "cache": "no-store",
        }
        bad = {k: v for k, v in seen.items() if k in want and v != want[k]}
        hsts = seen["hsts"] or ""
        if not re.fullmatch(r"max-age=\d{8,}(; includeSubDomains)?", hsts):
            bad["hsts"] = hsts
        if bad:
            wrong[name] = bad
    assert wrong == {}


async def test_the_nonce_is_new_on_every_response_and_matches_the_script_tag(
    client: httpx.AsyncClient,
) -> None:
    created = await client.post("/api/secrets", json=body())
    secret_id = created.json()["id"]
    pages = [await client.get(f"/s/{secret_id}") for _ in range(2)]
    pages += [await client.get("/")]
    api = [await client.post(f"/api/secrets/{new_secret_id()}/reveal") for _ in range(5)]
    nonces = [nonce_of(r) for r in [*pages, *api, created]]
    assert len(set(nonces)) == len(nonces), "a nonce was reused"
    for page in pages:
        assert f'<script type="module" nonce="{nonce_of(page)}"' in page.text
        assert page.text.count("<script") == 1


@pytest.mark.parametrize("path", ["/", "/s/abc"])
async def test_a_page_never_carries_a_script_without_the_nonce(
    client: httpx.AsyncClient, path: str
) -> None:
    html = (await client.get(path)).text
    assert not re.search(r"<script(?![^>]*nonce=)", html)
    assert " style=" not in html and "<style" not in html  # style-src 'self' allows neither
    assert not re.search(r"\son\w+=", html)  # no inline event handlers


SECRET_DETAIL = "redis password hunter2 at 10.1.2.3"


def assert_500_with_the_security_headers(res: httpx.Response) -> None:
    assert res.status_code == 500
    assert NONCE.sub("'nonce-N'", res.headers.get("content-security-policy", "")) == SPEC_CSP
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("referrer-policy") == "no-referrer"
    assert res.headers.get("cache-control") == "no-store"
    assert re.fullmatch(
        r"max-age=\d{8,}(; includeSubDomains)?", res.headers.get("strict-transport-security", "")
    )
    assert res.json() == {"detail": "internal server error"}
    assert SECRET_DETAIL not in res.text and "Traceback" not in res.text


def logged_the_exception(caplog: pytest.LogCaptureFixture) -> bool:
    return any(
        r.exc_info is not None and SECRET_DETAIL in str(r.exc_info[1]) for r in caplog.records
    )


async def test_a_500_from_a_route_has_the_headers_a_generic_body_and_a_log_line(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def boom(*_: object, **__: object) -> None:
        raise RuntimeError(SECRET_DETAIL)

    monkeypatch.setattr(SecretStorage, "create", boom)
    with caplog.at_level(logging.ERROR):
        res = await client.post("/api/secrets", json=body())
    assert_500_with_the_security_headers(res)
    assert logged_the_exception(caplog)


async def test_a_500_from_an_inner_middleware_has_the_headers_a_generic_body_and_a_log_line(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def boom(*_: object, **__: object) -> None:
        raise RuntimeError(SECRET_DETAIL)

    monkeypatch.setattr(CreateLimiter, "hit", boom)  # the limit middleware sits inside
    with caplog.at_level(logging.ERROR):
        res = await client.post("/api/secrets", json=body())
    assert_500_with_the_security_headers(res)
    assert logged_the_exception(caplog)


async def test_each_500_gets_its_own_nonce(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(*_: object, **__: object) -> None:
        raise RuntimeError(SECRET_DETAIL)

    monkeypatch.setattr(SecretStorage, "create", boom)
    nonces = [nonce_of(await client.post("/api/secrets", json=body())) for _ in range(3)]
    assert len(set(nonces)) == 3
