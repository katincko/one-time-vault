"""Find a known value (a canary) in a pile of bytes, under the encodings a leak could take."""

import base64
from urllib.parse import quote, quote_plus


def _b64_forms(needle: bytes) -> dict[str, bytes]:
    """Base64 text of `needle` as it appears inside a longer message, at any byte offset.

    Only the characters that do not depend on the neighbouring bytes are kept.
    """
    out: dict[str, bytes] = {}
    for alphabet, encode in (("std", base64.b64encode), ("url", base64.urlsafe_b64encode)):
        for offset in (0, 1, 2):
            text = encode(b"\x00" * offset + needle).rstrip(b"=")
            skip = {0: 0, 1: 2, 2: 3}[offset]  # leading chars that carry the filler bytes
            out[f"base64-{alphabet}+{offset}"] = text[skip : len(text) - 2]
    return out


def encodings(needle: bytes) -> dict[str, bytes]:
    """Every form of `needle` the search looks for, by name."""
    text = needle.decode("latin-1")
    return {
        "raw": needle,
        "hex-lower": needle.hex().encode(),
        "hex-upper": needle.hex().upper().encode(),
        **_b64_forms(needle),
        "percent": quote(needle, safe="").encode(),
        "percent-plus": quote_plus(needle).encode(),
        "utf-16-le": text.encode("utf-16-le"),
        "utf-16-be": text.encode("utf-16-be"),
        "reversed": needle[::-1],
    }


def find_leaks(haystack: bytes, needle: bytes) -> list[str]:
    """Names of the encodings of `needle` found in `haystack` (empty means clean)."""
    return [name for name, form in encodings(needle).items() if form and form in haystack]
