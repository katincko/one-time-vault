"""Limit on secret creation per client IP, counted in one Lua step.

The client IP is the last hop we trust. With `trusted_hops = N` (the proxies in front of the
app, each of which appends the address it saw to X-Forwarded-For) it is the Nth entry from the
right; everything to its left is whatever the client chose to send, so a forged header cannot
pick the bucket. With 0 hops the header is ignored. The app must only be reachable through those
proxies: a direct caller could write the whole header.

With `ip_header` (an edge such as Cloudflare that overwrites one header with the visitor's
address) the client is that header's single value, and neither the peer nor X-Forwarded-For is
looked at. A request without one valid address there is counted in the `NO_CLIENT_IP` bucket:
falling back to the peer would put every visitor in the proxy's bucket without a word, and
skipping the count would let anyone who reaches the app around the edge create without a limit.
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
NO_CLIENT_IP = "no-client-ip"  # not an address, so no client can land in it by its IP


def _bucket(address: str) -> str | None:
    """One normalized bucket for a text that should be an IP address, else None."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)  # ::ffff:a.b.c.d is the IPv4 client a.b.c.d, not a /64
    if isinstance(ip, ipaddress.IPv6Address):
        return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address) + "/64"
    return str(ip)


def client_ip(scope: Scope, trusted_hops: int, ip_header: str | None = None) -> str:
    """The bucket for this request: the trusted hop's address, else the socket peer.

    IPv6 clients are bucketed by /64, since one household or host owns a whole /64. An IPv4
    address mapped into IPv6 (`::ffff:a.b.c.d`) is the plain IPv4 one. The peer goes through the
    same normalization when the header is missing or not an address; free text is never a key.
    With `ip_header` the bucket is that header's one value, else `NO_CLIENT_IP`.
    """
    if ip_header is not None:
        values = Headers(scope=scope).getlist(ip_header)
        found = _bucket(values[0].strip()) if len(values) == 1 else None
        return found or NO_CLIENT_IP
    client = scope.get("client")
    peer = client[0] if client else "unknown"
    if trusted_hops > 0:
        entries = [
            e.strip()
            for line in Headers(scope=scope).getlist("x-forwarded-for")
            for e in line.split(",")
            if e.strip()
        ]
        if len(entries) >= trusted_hops:
            bucket = _bucket(entries[-trusted_hops])
            if bucket is not None:
                return bucket
    return _bucket(peer) or "unknown"


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

    def __init__(
        self, app: ASGIApp, limiter: CreateLimiter, trusted_hops: int, ip_header: str | None
    ) -> None:
        self.app = app
        self.limiter = limiter
        self.trusted_hops = trusted_hops
        self.ip_header = ip_header

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] == "POST" and scope["path"] == CREATE_PATH:
            retry_after = await self.limiter.hit(
                client_ip(scope, self.trusted_hops, self.ip_header)
            )
            if retry_after is not None:
                refusal = JSONResponse(
                    {"detail": "too many requests"},
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                )
                await refusal(scope, receive, send)
                return
        await self.app(scope, receive, send)
