"""The real pages in Chromium against the real server and a real Redis/Valkey.

Spec tests 1 (canaries), 4 (opening without clicking), 5 (incomplete link), 6 (tampering) and
13 (address bar), plus the crypto contract (labels, padding, interop with an independent
implementation).
"""

import os
import secrets

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from playwright.sync_api import expect
from redis import Redis as SyncRedis

from browser_kit import Tab, b64url, redis_bytes, request_bytes, stored_keys, unb64url
from canary import find_leaks
from conftest import LiveServer

# Test 1: neither the text nor the key ever reaches the server


def test_neither_the_text_nor_the_key_leaves_the_browser(
    tab: Tab, live_server: LiveServer, sync_redis: SyncRedis
) -> None:
    text_canary = f"TEXT-CANARY-{secrets.token_hex(12)}"
    needles = {"text": text_canary.encode()}

    def assert_clean(stage: str, requests: bytes, in_redis: bytes) -> None:
        logs = live_server.log()
        assert b"POST /api/secrets" in logs  # the log we search is the server's real log
        for where, haystack in (("requests", requests), ("redis", in_redis), ("server log", logs)):
            for what, needle in needles.items():
                assert find_leaks(haystack, needle) == [], f"{what} canary in {where}, {stage}"

    link = tab.create(f"my password is {text_canary}\nline two")
    key_canary = unb64url(link.split("#", 1)[1])  # the generated key, as a leak would carry it
    assert len(key_canary) == 32
    needles["key"] = key_canary
    in_redis = redis_bytes(sync_redis)  # sampled while the secret is stored
    assert len(stored_keys(sync_redis)) == 1 and len(in_redis) > 256
    posts = [r for r in tab.requests if r.method == "POST"]
    assert len(posts) == 1 and posts[0].post_data_buffer  # the create call carried something
    assert_clean("after create", request_bytes(tab.requests), in_redis)

    tab.open_link(link)
    tab.reveal()
    expect(tab.page.locator("#secret")).to_contain_text(text_canary)  # the flow really ran
    assert len([r for r in tab.requests if r.method == "POST"]) == 2
    assert_clean("after reveal", request_bytes(tab.requests), in_redis)


# Test 4 (browser half): a browser that opens the link without clicking


def test_opening_the_link_in_a_browser_consumes_nothing(tab: Tab, sync_redis: SyncRedis) -> None:
    link = tab.create("hello")
    tab.requests.clear()
    tab.open_link(link)
    expect(tab.page.locator("#reveal")).to_be_visible()
    tab.page.wait_for_load_state("networkidle")
    tab.page.wait_for_timeout(500)
    assert tab.api_calls() == []
    assert len(stored_keys(sync_redis)) == 1
    tab.reveal()
    expect(tab.page.locator("#secret")).to_have_text("hello")


# Test 5: a link without the whole key


def test_a_link_with_the_whole_key_offers_to_reveal(tab: Tab) -> None:
    link = tab.create("hello")
    tab.open_link(link)
    expect(tab.page.locator("#reveal")).to_be_visible()


@pytest.mark.parametrize(
    "fragment",
    [
        "",
        "#",
        "#short",
        "#" + "A" * 42,  # one character short of a whole key
        "#" + "A" * 44,  # one too many
        "#" + "A" * 43 + "=",
        "#" + "!" * 43,
        "#" + "A" * 42 + "B",  # 43 characters but not canonical base64url of 32 bytes
    ],
    ids=["none", "empty", "short", "cut", "long", "padded", "bad-chars", "non-canonical"],
)
def test_a_link_without_the_whole_key_says_so_and_never_calls_the_server(
    tab: Tab, sync_redis: SyncRedis, fragment: str
) -> None:
    link = tab.create("hello")
    secret_id = link.split("/s/")[1].split("#")[0]
    tab.requests.clear()
    tab.open_link(f"{tab.base}/s/{secret_id}{fragment}")
    expect(tab.page.locator("#status")).to_contain_text("Incomplete link")
    expect(tab.page.locator("#reveal")).to_be_hidden()
    tab.page.wait_for_timeout(300)  # a request made by the page script is recorded at once
    assert tab.api_calls() == []
    assert len(stored_keys(sync_redis)) == 1  # the secret is still there
    # and the complete link still works afterwards
    tab.open_link(link)
    tab.reveal()
    expect(tab.page.locator("#secret")).to_have_text("hello")


def test_completing_the_fragment_on_the_open_page_enables_reveal_without_a_reload(
    tab: Tab,
) -> None:
    link = tab.create("hello")
    base, key = link.split("#")
    tab.open_link(base)
    expect(tab.page.locator("#status")).to_contain_text("Incomplete link")
    tab.page.evaluate("(key) => { location.hash = key; }", key)  # same document, no reload
    expect(tab.page.locator("#reveal")).to_be_visible()
    tab.reveal()
    expect(tab.page.locator("#secret")).to_have_text("hello")
    tab.page.evaluate("(key) => { location.hash = key; }", key)  # too late: the secret is gone
    expect(tab.page.locator("#status")).to_contain_text("Secret opened")
    expect(tab.page.locator("#secret")).to_have_text("hello")


# Test 6: tampering


@pytest.mark.parametrize("where", ["iv", "first-ciphertext-byte", "middle", "tag"])
def test_an_altered_secret_is_refused(tab: Tab, sync_redis: SyncRedis, where: str) -> None:
    canary = f"TEXT-CANARY-{secrets.token_hex(8)}"
    link = tab.create(canary)
    (key,) = stored_keys(sync_redis)
    stored = bytearray(sync_redis.hget(key, "payload"))  # type: ignore[arg-type]
    index = {"iv": 0, "first-ciphertext-byte": 12, "middle": len(stored) // 2, "tag": -1}[where]
    stored[index] ^= 0x01
    sync_redis.hset(key, "payload", bytes(stored))
    tab.open_link(link)
    tab.reveal()
    expect(tab.page.locator("#status")).to_contain_text("Could not decrypt")
    expect(tab.page.locator("#secret")).to_be_hidden()
    assert canary not in tab.page.content()


def test_the_wrong_key_is_refused(tab: Tab) -> None:
    link = tab.create("hello")
    other = b64url(os.urandom(32))
    tab.open_link(link.split("#")[0] + "#" + other)
    tab.reveal()
    expect(tab.page.locator("#status")).to_contain_text("Could not decrypt")
    expect(tab.page.locator("#secret")).to_be_hidden()


# Test 13: the address bar


def test_the_fragment_is_removed_from_the_address_bar_after_opening(tab: Tab) -> None:
    link = tab.create("hello")
    tab.open_link(link)
    assert tab.page.evaluate("location.hash") != ""
    tab.reveal()
    expect(tab.page.locator("#secret")).to_have_text("hello")
    assert tab.page.evaluate("location.hash") == ""
    assert "#" not in tab.page.url
    assert tab.page.url == link.split("#")[0]


def test_the_fragment_is_removed_when_the_secret_is_already_gone(tab: Tab) -> None:
    link = tab.create("hello")
    tab.open_link(link)
    tab.reveal()
    expect(tab.page.locator("#secret")).to_have_text("hello")
    tab.page.goto("about:blank")  # a fresh visit, not a fragment change on the open page
    tab.open_link(link)  # second visit: 404
    tab.reveal()
    expect(tab.page.locator("#status")).to_contain_text("already read")
    assert "#" not in tab.page.url


# The crypto contract


def test_text_round_trips_including_unicode_and_the_size_limit(tab: Tab) -> None:
    for text in ("a", "line1\nline2\n", "pässword 🔐 日本語", "x" * 10 * 1024):
        link = tab.create(text)
        tab.open_link(link)
        tab.reveal()
        expect(tab.page.locator("#secret")).to_be_visible()
        assert tab.page.locator("#secret").text_content() == text


def test_text_over_10kb_is_refused_in_the_browser_before_any_request(tab: Tab) -> None:
    tab.page.goto(tab.base + "/")
    tab.requests.clear()
    tab.page.fill("#text", "x" * (10 * 1024 + 1))
    tab.page.click("#create")
    expect(tab.page.locator("#error")).to_contain_text("longer than 10 KB")
    assert tab.api_calls() == []


def test_ciphertext_size_shows_only_the_block_count(tab: Tab) -> None:
    def sent_ciphertext_chars(text: str) -> int:
        tab.requests.clear()
        tab.create(text)
        (post,) = [r for r in tab.requests if r.method == "POST"]
        return len(post.post_data_json["ciphertext"])  # type: ignore[index]

    assert sent_ciphertext_chars("a") == sent_ciphertext_chars("b" * 200)  # same block
    assert sent_ciphertext_chars("a") == sent_ciphertext_chars("a" * 255)  # 255 + 0x80 fits
    assert sent_ciphertext_chars("a" * 256) > sent_ciphertext_chars("a")  # next block


KNOWN_KEY = bytes(range(32))

ENCRYPT_IN_BROWSER = """
async ([keyText, text]) => {
  const m = await import('/static/vault-crypto.js');
  const key = m.b64urlDecode(keyText);
  const sealed = await m.encrypt(text, key);
  const keys = await m.deriveKeys(key);
  return {
    iv: m.b64urlEncode(sealed.iv),
    ciphertext: m.b64urlEncode(sealed.ciphertext),
    password: m.b64urlEncode(keys.password),
  };
}
"""


def hkdf(label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(KNOWN_KEY)


def test_the_browser_uses_hkdf_labels_and_aes_gcm_like_an_independent_implementation(
    tab: Tab,
) -> None:
    tab.page.goto(tab.base + "/")
    text = "interop ✓ " + "z" * 300
    out = tab.page.evaluate(ENCRYPT_IN_BROWSER, [b64url(KNOWN_KEY), text])
    iv, ciphertext = unb64url(out["iv"]), unb64url(out["ciphertext"])
    assert len(iv) == 12 and len(ciphertext) % 256 == 16
    padded = AESGCM(hkdf(b"encryption")).decrypt(iv, ciphertext, None)
    assert len(padded) % 256 == 0
    assert padded.rstrip(b"\x00")[-1] == 0x80
    assert padded.rstrip(b"\x00")[:-1].decode() == text
    assert unb64url(out["password"]) == hkdf(b"password")
    assert hkdf(b"password") != hkdf(b"encryption")
