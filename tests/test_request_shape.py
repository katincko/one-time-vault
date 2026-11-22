"""Positive control for the structural request check: it must refuse what a leak would look like."""

import json
import os

import pytest

from browser_kit import b64url
from request_shape import ALLOWED_HEADERS, request_problems

BASE = "http://127.0.0.1:8000"
JSON_HEADERS = {"content-type": "application/json", "host": "x", "content-length": "1"}
KEY = os.urandom(32)
ID = "A" * 22


def create_body(**extra: object) -> bytes:
    body = {"iv": b64url(os.urandom(12)), "ciphertext": b64url(os.urandom(272)), "expires_in": "1d"}
    return json.dumps({**body, **extra}).encode()


def create_problems(body: bytes, headers: dict[str, str] | None = None) -> list[str]:
    return request_problems("POST", BASE + "/api/secrets", headers or JSON_HEADERS, body)


def test_the_requests_the_page_makes_are_clean() -> None:
    assert create_problems(create_body()) == []
    protected = create_body(password_verifier=b64url(os.urandom(32)), iterations=600_000)
    assert create_problems(protected) == []
    reveal = f"{BASE}/api/secrets/{ID}/reveal"
    assert request_problems("POST", reveal, {"host": "x"}, None) == []
    verifier = json.dumps({"verifier": b64url(os.urandom(32))}).encode()
    assert request_problems("POST", reveal, JSON_HEADERS, verifier) == []
    assert request_problems("GET", f"{BASE}/s/{ID}", {"host": "x"}, None) == []
    assert request_problems("GET", f"{BASE}/static/open.js", {"host": "x"}, None) == []


def test_the_key_in_a_header_in_hex_with_colons_is_refused() -> None:
    hexed = ":".join(f"{b:02x}" for b in KEY)
    problems = create_problems(create_body(), {**JSON_HEADERS, "x-trace": hexed})
    assert problems == ["header x-trace is not allowed"]


def test_the_key_as_a_json_array_of_decimals_is_refused() -> None:
    problems = create_problems(create_body(k=list(KEY)))
    assert any("body keys" in p for p in problems)


def test_the_key_hidden_in_a_legitimate_field_is_refused() -> None:
    text = create_body().replace(b'"1d"', b'"1d' + b64url(KEY).encode() + b'"')
    assert any("expires_in" in p for p in create_problems(text))
    array = json.loads(create_body())
    array["iv"] = list(KEY)
    assert any("iv" in p for p in create_problems(json.dumps(array).encode()))


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/?k=1"), ("GET", f"/s/{ID}#k"), ("GET", "/other"), ("PUT", "/api/secrets"),
     ("POST", "/api/secrets/x/reveal"), ("GET", "/api/secrets")],
)  # fmt: skip
def test_a_request_that_is_not_one_the_page_makes_is_refused(method: str, path: str) -> None:
    assert request_problems(method, BASE + path, {"host": "x"}, None) != []


def test_the_reveal_call_with_extra_keys_or_a_wrong_type_is_refused() -> None:
    reveal = f"{BASE}/api/secrets/{ID}/reveal"
    extra = json.dumps({"verifier": b64url(os.urandom(32)), "k": 1}).encode()
    assert request_problems("POST", reveal, JSON_HEADERS, extra) != []
    wrong = json.dumps({"verifier": list(KEY)}).encode()
    assert request_problems("POST", reveal, JSON_HEADERS, wrong) != []
    assert request_problems("POST", reveal, {"host": "x"}, b"") == []


def test_the_allowed_header_list_has_no_header_a_page_script_could_use_for_a_key() -> None:
    assert not {h for h in ALLOWED_HEADERS if h.startswith("x-") or h in ("cookie", "referer")}
