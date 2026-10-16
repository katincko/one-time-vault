"""Positive control for test 1: the finder must find each encoding, or "no leak" means nothing."""

import base64
import os

import pytest

from canary import encodings, find_leaks

EXPECTED = [
    "raw",
    "hex-lower",
    "hex-upper",
    "base64-std+0",
    "base64-std+1",
    "base64-std+2",
    "base64-url+0",
    "base64-url+1",
    "base64-url+2",
    "percent",
    "percent-plus",
    "utf-16-le",
    "utf-16-be",
    "reversed",
]
NEEDLES = [b"TEXT-CANARY-0123456789abcdef", bytes(range(200, 232))]
NOISE = b"GET /api/secrets HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n" * 3


def test_the_finder_looks_for_every_expected_encoding() -> None:
    for needle in NEEDLES:
        assert set(encodings(needle)) == set(EXPECTED)


@pytest.mark.parametrize("name", EXPECTED)
@pytest.mark.parametrize("needle", NEEDLES)
def test_each_encoding_is_found_inside_noise(name: str, needle: bytes) -> None:
    form = encodings(needle)[name]
    assert name in find_leaks(NOISE + form + NOISE, needle)


@pytest.mark.parametrize("prefix_len", [0, 1, 2, 3, 4, 5])
@pytest.mark.parametrize("encode", [base64.b64encode, base64.urlsafe_b64encode])
def test_base64_is_found_at_any_alignment(prefix_len: int, encode: object) -> None:
    needle = NEEDLES[0]
    assert callable(encode)
    message = os.urandom(prefix_len) + needle + os.urandom(7)
    assert any(n.startswith("base64") for n in find_leaks(encode(message), needle))


@pytest.mark.parametrize("needle", NEEDLES)
def test_clean_noise_has_no_leak(needle: bytes) -> None:
    assert find_leaks(NOISE + os.urandom(2000), needle) == []
