"""The access password in real Chromium (spec test 7, browser half), and the page CSP at work."""

import hashlib
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from playwright.sync_api import expect
from redis import Redis as SyncRedis

from browser_kit import Tab, b64url, redis_bytes, request_bytes, stored_keys, unb64url
from canary import find_leaks
from conftest import LiveServer

PASSWORD = "correct horse battery staple"


def open_and_reveal(tab: Tab, link: str) -> None:
    tab.open_link(link)
    tab.reveal()


def enter_password(tab: Tab, password: str) -> None:
    tab.page.fill("#access-password", password)
    tab.page.click("#open-secret")


def test_a_protected_secret_asks_for_the_password_and_opens_with_it(
    tab: Tab, sync_redis: SyncRedis
) -> None:
    link = tab.create("behind a password", password=PASSWORD)
    open_and_reveal(tab, link)
    expect(tab.page.locator("#password-form")).to_be_visible()
    expect(tab.page.locator("#status")).to_contain_text("password")
    expect(tab.page.locator("#secret")).to_be_hidden()
    assert len(stored_keys(sync_redis)) == 1  # asking for the password consumed nothing
    enter_password(tab, PASSWORD)
    expect(tab.page.locator("#secret")).to_have_text("behind a password")
    expect(tab.page.locator("#password-form")).to_be_hidden()
    assert stored_keys(sync_redis) == []
    assert tab.page.evaluate("location.hash") == ""


def test_a_wrong_password_counts_down_and_the_right_one_still_works(tab: Tab) -> None:
    link = tab.create("hello", password=PASSWORD)
    open_and_reveal(tab, link)
    enter_password(tab, "nope")
    expect(tab.page.locator("#status")).to_contain_text("Wrong password. 4 attempts left")
    expect(tab.page.locator("#password-form")).to_be_visible()
    enter_password(tab, "still nope")
    expect(tab.page.locator("#status")).to_contain_text("3 attempts left")
    enter_password(tab, PASSWORD)
    expect(tab.page.locator("#secret")).to_have_text("hello")


def test_five_wrong_passwords_destroy_the_secret_and_the_page_says_so(
    tab: Tab, sync_redis: SyncRedis
) -> None:
    link = tab.create("hello", password=PASSWORD)
    open_and_reveal(tab, link)
    for n in range(5):
        enter_password(tab, f"wrong {n}")
        expect(tab.page.locator("#status")).to_contain_text(
            "Wrong password" if n < 4 else "deleted from the server"
        )
    expect(tab.page.locator("#password-form")).to_be_hidden()
    assert stored_keys(sync_redis) == []
    assert "#" not in tab.page.url
    tab.page.goto("about:blank")  # a fresh visit, not a fragment change on the open page
    tab.open_link(link)  # the owner of the right password is too late
    tab.reveal()
    expect(tab.page.locator("#status")).to_contain_text("already read")


def test_the_password_never_reaches_the_server(
    tab: Tab, live_server: LiveServer, sync_redis: SyncRedis
) -> None:
    canary = f"PASSWORD-CANARY-{secrets.token_hex(12)}"
    link = tab.create("some text", password=canary)
    key = unb64url(link.split("#", 1)[1])
    in_redis = redis_bytes(sync_redis)  # sampled while the secret is stored
    assert len(in_redis) > 256
    posts = [r for r in tab.requests if r.method == "POST"]
    sent = posts[0].post_data_json
    assert sent is not None and len(unb64url(sent["password_verifier"])) == 32
    open_and_reveal(tab, link)
    enter_password(tab, canary)
    expect(tab.page.locator("#secret")).to_have_text("some text")
    assert len([r for r in tab.requests if r.method == "POST"]) == 3  # create, ask, answer
    logs = live_server.log()
    assert b"POST /api/secrets" in logs
    for where, haystack in (
        ("requests", request_bytes(tab.requests)),
        ("redis", in_redis),
        ("server log", logs),
    ):
        assert find_leaks(haystack, canary.encode()) == [], f"password canary in {where}"
        assert find_leaks(haystack, key) == [], f"key canary in {where}"


def test_the_verifier_is_pbkdf2_of_the_password_salted_with_the_password_subkey(
    tab: Tab,
) -> None:
    """Checked against Python's own PBKDF2, so the browser cannot agree only with itself."""
    key = bytes(range(32))
    tab.page.goto(tab.base + "/")
    out = tab.page.evaluate(
        """async ([keyText, password, iterations]) => {
          const m = await import('/static/vault-crypto.js');
          const v = await m.passwordVerifier(password, m.b64urlDecode(keyText), iterations);
          return m.b64urlEncode(v);
        }""",
        [b64url(key), PASSWORD, 600_000],
    )
    salt = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"password").derive(key)
    assert unb64url(out) == hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt, 600_000, 32)


def test_the_same_password_typed_in_two_unicode_forms_gives_the_same_verifier(tab: Tab) -> None:
    tab.page.goto(tab.base + "/")
    out = tab.page.evaluate(
        """async () => {
          const m = await import('/static/vault-crypto.js');
          const key = new Uint8Array(32);
          const a = await m.passwordVerifier('p\\u00e4ss', key, 600000);
          const b = await m.passwordVerifier('pa\\u0308ss', key, 600000);
          const c = await m.passwordVerifier('other', key, 600000);
          return [m.b64urlEncode(a) === m.b64urlEncode(b), m.b64urlEncode(a) === m.b64urlEncode(c)];
        }"""
    )
    assert out == [True, False]


RECORD_KEY_FLAGS = """
(() => {
  for (const name of ['importKey', 'deriveKey']) {
    const original = crypto.subtle[name].bind(crypto.subtle);
    crypto.subtle[name] = (...args) => {
      const algo = name === 'importKey' ? args[2] : args[2];
      window.__recordKey(JSON.stringify({ name, algo: algo.name ?? algo, extractable: args[3] }));
      return original(...args);
    };
  }
})();
"""


def test_no_key_the_pages_make_is_extractable_in_the_whole_flow(tab: Tab) -> None:
    calls: list[str] = []
    tab.page.expose_function("__recordKey", lambda s: calls.append(s))
    tab.page.add_init_script(RECORD_KEY_FLAGS)
    link = tab.create("flow", password=PASSWORD)
    open_and_reveal(tab, link)
    enter_password(tab, PASSWORD)
    expect(tab.page.locator("#secret")).to_have_text("flow")
    kinds = {c.split('"algo":"')[1].split('"')[0] for c in calls}
    assert {"HKDF", "AES-GCM", "PBKDF2"} <= kinds  # every kind of key was made
    assert [c for c in calls if '"extractable":false' not in c] == []


def test_the_pages_run_under_the_csp_without_a_violation(tab: Tab) -> None:
    problems: list[str] = []
    tab.page.on(
        "console",
        lambda m: problems.append(m.text) if "Content Security Policy" in m.text else None,
    )
    link = tab.create("flow", password=PASSWORD)
    open_and_reveal(tab, link)
    enter_password(tab, PASSWORD)
    expect(tab.page.locator("#secret")).to_have_text("flow")
    assert problems == []
