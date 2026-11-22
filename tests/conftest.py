import asyncio
import base64
import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from playwright.sync_api import Browser, sync_playwright
from redis import Redis as SyncRedis
from redis.asyncio import Redis
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

from browser_kit import Tab

ROOT = Path(__file__).parent.parent


def _compose_redis_image() -> str:
    """The redis image of compose.yaml, tag and digest: one pin for the app and the tests."""
    match = re.search(
        r"image: (redis:\S+@sha256:[0-9a-f]{64})", (ROOT / "compose.yaml").read_text()
    )
    assert match, "compose.yaml does not pin redis by digest"
    return match.group(1)


# Pinned by digest: the suite runs against the real servers, never a fake, and always the same.
IMAGES = [
    _compose_redis_image(),
    "valkey/valkey:8.0@sha256:fcb69dfef81599baefeee6cdd0b8339b61b7983a8ee08d307e44844db5bd7047",
]


@pytest.fixture(scope="session", params=IMAGES, ids=["redis-7.4", "valkey-8.0"])
def server_url(request: pytest.FixtureRequest) -> Iterator[str]:
    container = (
        DockerContainer(request.param)
        .with_exposed_ports(6379)
        .waiting_for(LogMessageWaitStrategy("Ready to accept connections"))
    )
    with container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}"


@pytest_asyncio.fixture
async def redis(server_url: str) -> AsyncIterator[Redis]:
    client: Redis = Redis.from_url(server_url, max_connections=200, socket_connect_timeout=30)
    # Warm the pool: opening 50 sockets at once through Docker Desktop is slow and flaky.
    await asyncio.gather(*(client.ping() for _ in range(60)))
    await client.flushall()
    yield client
    await client.aclose()


@dataclass(frozen=True)
class LiveServer:
    """The real app in its own process, on a real port, with its log in a file."""

    url: str
    redis_url: str
    log_path: Path

    def log(self) -> bytes:
        return self.log_path.read_bytes()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# Server keys for the tests: version 1 is the old one, version 2 the current one.
KEY_V1 = bytes(range(32))
KEY_V2 = bytes(range(32, 64))
SERVER_KEYS = f"2:{_b64(KEY_V2)},1:{_b64(KEY_V1)}"


@contextmanager
def run_server(
    redis_url: str, log_path: Path, extra_env: dict[str, str] | None = None
) -> Iterator[LiveServer]:
    """The real app under uvicorn in its own process. Our own client-IP logic is the only one."""
    port = _free_port()
    env = {
        **os.environ,
        "OTV_REDIS_URL": redis_url,
        "OTV_SERVER_KEYS": SERVER_KEYS,
        "OTV_CREATE_LIMIT": "100000",  # the browser tests create hundreds of secrets
        "PYTHONUNBUFFERED": "1",
        **(extra_env or {}),
    }
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "--factory",
                "one_time_vault.app:app_from_env",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "debug",
                "--no-proxy-headers",
            ],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        url = f"http://127.0.0.1:{port}"
        try:
            deadline = time.time() + 30
            while True:
                try:
                    httpx.get(url + "/", timeout=1).raise_for_status()
                    break
                except httpx.HTTPError:
                    assert proc.poll() is None and time.time() < deadline, "server did not start"
                    time.sleep(0.2)
            yield LiveServer(url=url, redis_url=redis_url, log_path=log_path)
        finally:
            proc.terminate()
            proc.wait(timeout=10)


@pytest.fixture(scope="session")
def live_server(server_url: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[LiveServer]:
    with run_server(server_url, tmp_path_factory.mktemp("server") / "server.log") as server:
        yield server


@pytest.fixture
def sync_redis(server_url: str) -> Iterator[SyncRedis]:
    """Plain blocking client for the Playwright tests (they cannot run inside the asyncio loop)."""
    client = SyncRedis.from_url(server_url)
    client.flushall()
    yield client
    client.close()


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    # Module scope on purpose: while sync Playwright is started, the thread looks like it has a
    # running event loop and every asyncio test (pytest-asyncio) errors out.
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture
def tab(browser: Browser, live_server: LiveServer, sync_redis: SyncRedis) -> Iterator[Tab]:
    context = browser.new_context()
    t = Tab(context.new_page(), live_server.url)
    context.on("request", lambda r: t.requests.append(r))
    yield t
    context.close()
