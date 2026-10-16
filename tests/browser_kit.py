"""Shared by the browser test files: a tab wrapper and byte collectors for the leak checks."""

import base64
from dataclasses import dataclass, field

from playwright.sync_api import Page, Request, expect
from redis import Redis as SyncRedis


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass
class Tab:
    page: Page
    base: str
    requests: list[Request] = field(default_factory=list)

    def create(self, text: str, expires: str = "1d", password: str | None = None) -> str:
        """Fill the form like a person and return the one-time link it shows."""
        self.page.goto(self.base + "/")
        self.page.fill("#text", text)
        self.page.check(f'input[name="expires_in"][value="{expires}"]')
        if password is not None:
            self.page.fill("#password", password)
        self.page.click("#create")
        expect(self.page.locator("#result")).to_be_visible()
        return self.page.input_value("#link")

    def open_link(self, link: str) -> None:
        self.page.goto(link)

    def reveal(self) -> None:
        self.page.click("#reveal")

    def api_calls(self) -> list[Request]:
        return [r for r in self.requests if "/api/" in r.url]


def stored_keys(r: SyncRedis) -> list[bytes]:
    return sorted(r.scan_iter("ovv:s:*"))


def as_bytes(value: bytes | str) -> bytes:
    return value if isinstance(value, bytes) else value.encode()


def redis_bytes(r: SyncRedis) -> bytes:
    """Every key name and every stored value, as bytes."""
    out: list[bytes] = []
    for key in stored_keys(r):
        out.append(key)
        for field_name, value in r.hgetall(key).items():
            out += [as_bytes(field_name), as_bytes(value)]
    return b"\n".join(out)


def request_bytes(requests: list[Request]) -> bytes:
    """Everything the browser sent: request line, every header, body."""
    out = []
    for r in requests:
        out.append(f"{r.method} {r.url}".encode())
        out += [f"{k}: {v}".encode() for k, v in r.all_headers().items()]
        out.append(r.post_data_buffer or b"")
    return b"\n".join(out)
