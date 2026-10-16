import asyncio
from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio
from redis.asyncio import Redis
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

# Pinned tags: the suite runs against the real servers, never a fake.
IMAGES = ["redis:7.4", "valkey/valkey:8.0"]


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
