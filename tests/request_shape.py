"""What the page may send, as a structure: headers, URL paths and the API bodies.

The canary search (`canary.py`) looks for a known value under known encodings, so a new encoding
slips through. This check does not look for anything: it says what a request may contain, and
everything else is a finding. A key or a text hidden in a new header, in the value of an allowed
header, in a new body key, a query string, or in a legitimate field with a wrong length or
encoding fails here whatever its encoding. Body values are checked by the server's own request
models, so the server and this check cannot disagree on what a valid body is.
"""

import json
import re
from collections.abc import Mapping
from typing import Any

from playwright.sync_api import Request
from pydantic import BaseModel, ValidationError

from one_time_vault.app import CreateRequest, RevealRequest

# Header names and the shape of each value, measured on the real flow (create, open, reveal,
# password) in Chromium. The page script sets only content-type; the others come from the browser.
# A value is checked as well as a name: a key can ride in the text of an allowed header.
_ACCEPT_PAGE = (
    r"text/html,application/xhtml\+xml,application/xml;q=0\.9,image/jxl,image/avif,image/webp,"
    r"image/apng,\*/\*;q=0\.8,application/signed-exchange;v=b3;q=0\.7"
)
_LOCAL_HOST = r"127\.0\.0\.1:\d{1,5}"
_HEADER_VALUES: dict[str, str] = {
    "accept": rf"{_ACCEPT_PAGE}|\*/\*|text/css,\*/\*;q=0\.1",
    "accept-encoding": r"gzip, deflate, br, zstd",
    "connection": r"keep-alive",
    "content-length": r"\d{1,6}",
    "content-type": r"application/json",
    "host": _LOCAL_HOST,
    "origin": rf"http://{_LOCAL_HOST}",
    # Chromium's brands: two fixed names and a short "grease" one that changes with the version.
    "sec-ch-ua": r'"Not[^"]{1,14}";v="\d+", "Chromium";v="\d+", "HeadlessChrome";v="\d+"',
    "sec-ch-ua-mobile": r"\?0",
    "sec-ch-ua-platform": r'"(Linux|macOS|Windows)"',
    "sec-fetch-dest": r"document|empty|script|style",
    "sec-fetch-mode": r"cors|navigate|no-cors",
    "sec-fetch-site": r"none|same-origin",
    "sec-fetch-user": r"\?1",
    "upgrade-insecure-requests": r"1",
    "user-agent": (
        r"Mozilla/5\.0 \([A-Za-z0-9 ;._]{1,30}\) AppleWebKit/537\.36 \(KHTML, like Gecko\) "
        r"HeadlessChrome/\d+(\.\d+){3} Safari/537\.36"
    ),
}
ALLOWED_HEADERS = frozenset(_HEADER_VALUES)
_HEADER_PATTERNS = {name: re.compile(value) for name, value in _HEADER_VALUES.items()}

_ID = r"[A-Za-z0-9_-]{22}"
_PAGE_PATHS = re.compile(rf"/|/s/{_ID}|/static/[a-z0-9-]+\.(js|css)")
_REVEAL_PATH = re.compile(rf"/api/secrets/{_ID}/reveal")
_CREATE_KEYS = {"iv", "ciphertext", "expires_in"}
_CREATE_PASSWORD_KEYS = _CREATE_KEYS | {"password_verifier", "iterations"}


def _body_problems(
    body: bytes, model: type[BaseModel], allowed_key_sets: list[set[str]]
) -> list[str]:
    """The keys, then every value against the server's own model (lengths, padding, encoding)."""
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
    try:
        model.model_validate_json(body)
    except ValidationError as exc:
        problems += [f"body field {'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()]
    return problems


def request_problems(
    method: str, url: str, headers: Mapping[str, str], body: bytes | None
) -> list[str]:
    """Everything wrong with one request the page sent; empty means it has the expected shape."""
    problems = [f"header {name} is not allowed" for name in headers if name not in ALLOWED_HEADERS]
    problems += [
        f"header {name} has a value that is not the expected one"
        for name, value in headers.items()
        if name in _HEADER_PATTERNS and not _HEADER_PATTERNS[name].fullmatch(value)
    ]
    path = re.sub(r"^https?://[^/]+", "", url)
    if "?" in path or "#" in path:
        problems.append("the URL has a query string or a fragment")
    if path == "/api/secrets" and method == "POST":
        if headers.get("content-type") != "application/json":
            problems.append("the create call is not application/json")
        keys = [_CREATE_KEYS, _CREATE_PASSWORD_KEYS]
        problems += _body_problems(body or b"", CreateRequest, keys)
    elif _REVEAL_PATH.fullmatch(path) and method == "POST":
        if body:  # with a verifier it is JSON; without one there is no body at all
            if headers.get("content-type") != "application/json":
                problems.append("the reveal call is not application/json")
            problems += _body_problems(body, RevealRequest, [{"verifier"}])
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
