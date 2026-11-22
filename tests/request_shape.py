"""What the page may send, as a structure: header names, URL paths and the keys of API bodies.

The canary search (`canary.py`) looks for a known value under known encodings, so a new encoding
slips through. This check does not look for anything: it says what a request may contain, and
everything else is a finding. A key or a text hidden in a new header, a new body key, a query
string, or a legitimate field with a wrong shape fails here whatever its encoding.
"""

import json
import re
from collections.abc import Mapping
from typing import Any

from playwright.sync_api import Request

# Header names Chromium sends for these pages, measured on the real flow (create, open, reveal,
# password). The page script sets only content-type; the others come from the browser.
ALLOWED_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "connection",
        "content-length",
        "content-type",
        "host",
        "origin",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "upgrade-insecure-requests",
        "user-agent",
    }
)

_ID = r"[A-Za-z0-9_-]{22}"
_PAGE_PATHS = re.compile(rf"/|/s/{_ID}|/static/[a-z0-9-]+\.(js|css)")
_REVEAL_PATH = re.compile(rf"/api/secrets/{_ID}/reveal")
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_BASE64URL_FIELDS = {"iv", "ciphertext", "verifier", "password_verifier"}
_CREATE_KEYS = {"iv", "ciphertext", "expires_in"}
_CREATE_PASSWORD_KEYS = _CREATE_KEYS | {"password_verifier", "iterations"}


def _body_problems(body: bytes, allowed_key_sets: list[set[str]]) -> list[str]:
    try:
        data: Any = json.loads(body)
    except ValueError:
        return ["body is not JSON"]
    if not isinstance(data, dict):
        return ["body is not a JSON object"]
    problems = []
    if set(data) not in allowed_key_sets:
        problems.append(
            f"body keys {sorted(data)} are not one of {[sorted(k) for k in allowed_key_sets]}"
        )
    for key, value in data.items():
        if key in _BASE64URL_FIELDS and not (isinstance(value, str) and _B64URL.fullmatch(value)):
            problems.append(f"body field {key} is not a base64url string")
        if key == "expires_in" and value not in ("1h", "1d", "7d"):
            problems.append("body field expires_in is not one of 1h, 1d, 7d")
        if key == "iterations" and (type(value) is not int):
            problems.append("body field iterations is not an integer")
    return problems


def request_problems(
    method: str, url: str, headers: Mapping[str, str], body: bytes | None
) -> list[str]:
    """Everything wrong with one request the page sent; empty means it has the expected shape."""
    problems = [f"header {name} is not allowed" for name in headers if name not in ALLOWED_HEADERS]
    path = re.sub(r"^https?://[^/]+", "", url)
    if "?" in path or "#" in path:
        problems.append("the URL has a query string or a fragment")
    if path == "/api/secrets" and method == "POST":
        if headers.get("content-type") != "application/json":
            problems.append("the create call is not application/json")
        problems += _body_problems(body or b"", [_CREATE_KEYS, _CREATE_PASSWORD_KEYS])
    elif _REVEAL_PATH.fullmatch(path) and method == "POST":
        if body:  # with a verifier it is JSON; without one there is no body at all
            if headers.get("content-type") != "application/json":
                problems.append("the reveal call is not application/json")
            problems += _body_problems(body, [{"verifier"}])
    elif method == "GET" and _PAGE_PATHS.fullmatch(path):
        if body:
            problems.append("a GET carries a body")
    else:
        problems.append(f"{method} {path} is not a request the page may make")
    return problems


def assert_requests_have_the_expected_shape(requests: list[Request]) -> None:
    """Every request the page made passes `request_problems`; the findings are listed together."""
    found = {
        f"{r.method} {r.url}: {p}"
        for r in requests
        for p in request_problems(r.method, r.url, r.all_headers(), r.post_data_buffer)
    }
    assert not found, "\n".join(sorted(found))
