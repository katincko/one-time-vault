"""Limit on secret creation per client IP, counted in one Lua step.

The client IP is the last hop we trust. With `trusted_hops = N` (the proxies in front of the
app, each of which appends the address it saw to X-Forwarded-For) it is the Nth entry from the
right; everything to its left is whatever the client chose to send, so a forged header cannot
pick the bucket. With 0 hops the header is ignored. The app must only be reachable through those
proxies: a direct caller could write the whole header.
"""

import ipaddress
from typing import Any

from redis.asyncio import Redis
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from one_time_vault import scripts

KEY_PREFIX = "ovv:rl:"
CREATE_PATH = "/api/secrets"


def client_ip(scope: Scope, trusted_hops: int) -> str:
    """The bucket for this request: the trusted hop's address, else the socket peer.

    IPv6 clients are bucketed by /64, since one household or host owns a whole /64. An IPv4
    address mapped into IPv6 (`::ffff:a.b.c.d`) is the plain IPv4 one.
    """
    client = scope.get("client")
    peer = client[0] if client else "unknown"
    address = peer
    if trusted_hops > 0:
        entries = [
            e.strip()
            for line in Headers(scope=scope).getlist("x-forwarded-for")
            for e in line.split(",")
            if e.strip()
        ]
        if len(entries) >= trusted_hops:
            address = entries[-trusted_hops]
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return peer  # not an address: never let free text become a key
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)  # ::ffff:a.b.c.d is the IPv4 client a.b.c.d, not a /64
    if isinstance(ip, ipaddress.IPv6Address):
        return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address) + "/64"
    return str(ip)


class CreateLimiter:
    def __init__(self, redis: Redis, *, limit: int, window_seconds: int) -> None:
        self._count = redis.register_script(scripts.RATE_COUNT)
        self._limit = limit
        self._window_ms = window_seconds * 1000

    async def hit(self, bucket: str) -> int | None:
        """Count one creation attempt. None if allowed, else the seconds until the window ends."""
        out: Any = await self._count(keys=[KEY_PREFIX + bucket], args=[self._window_ms])
        count, left_ms = int(out[0]), int(out[1])
        return None if count <= self._limit else max(1, -(-left_ms // 1000))


class CreateLimitMiddleware:
    """429 for POST /api/secrets over the limit. It counts every attempt, even a refused body."""

    def __init__(self, app: ASGIApp, limiter: CreateLimiter, trusted_hops: int) -> None:
        self.app = app
        self.limiter = limiter
        self.trusted_hops = trusted_hops

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] == "POST" and scope["path"] == CREATE_PATH:
            retry_after = await self.limiter.hit(client_ip(scope, self.trusted_hops))
            if retry_after is not None:
                refusal = JSONResponse(
                    {"detail": "too many requests"},
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                )
                await refusal(scope, receive, send)
                return
        await self.app(scope, receive, send)
