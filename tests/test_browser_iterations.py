"""The PBKDF2 cost comes from the server, so the page checks it before it spends a CPU on it.

A stored value outside the limits the server itself enforces (`keyring.py`) is a bug or an
attack on the opener's browser: the page refuses it and sends nothing more. A derivation that
fails shows an error instead of staying on "Checking the password.".
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest
from playwright.sync_api import Route, expect
from redis import Redis as SyncRedis

from browser_kit import Tab, stored_keys
from one_time_vault.keyring import MAX_ITERATIONS, MIN_ITERATIONS

STATIC = Path(__file__).parent.parent / "src" / "one_time_vault" / "static"
PASSWORD = "correct horse battery staple"


def server_asks_for_a_password(tab: Tab, iterations: Any) -> None:
    """Every reveal answers `password_required` with this cost, without touching the secret."""

    def answer(route: Route) -> None:
        route.fulfill(
            status=403,
            content_type="application/json",
            body=json.dumps({"error": "password_required", "iterations": iterations}),
        )

    tab.page.route(re.compile(r"/api/secrets/[^/]+/reveal$"), answer)


def reveal_calls(tab: Tab) -> int:
    return len([r for r in tab.api_calls() if r.url.endswith("/reveal")])


def test_the_browser_limits_are_the_ones_the_server_enforces() -> None:
    source = (STATIC / "vault-crypto.js").read_text(encoding="utf-8")
    pattern = r"export const (MIN_ITERATIONS|MAX_ITERATIONS) = ([\d_]+);"
    found = {name: int(value.replace("_", "")) for name, value in re.findall(pattern, source)}
    assert found == {"MIN_ITERATIONS": MIN_ITERATIONS, "MAX_ITERATIONS": MAX_ITERATIONS}


@pytest.mark.parametrize(
    "iterations",
    [1, MIN_ITERATIONS - 1, MAX_ITERATIONS + 1, 2**31, -600_000, 600_000.5, "700000", None, 0],
    ids=["one", "below", "above", "huge", "negative", "fraction", "text", "null", "zero"],
)
def test_an_iteration_count_outside_the_limits_is_refused_and_nothing_more_is_sent(
    tab: Tab, sync_redis: SyncRedis, iterations: Any
) -> None:
    link = tab.create("hello")
    server_asks_for_a_password(tab, iterations)
    tab.requests.clear()
    tab.open_link(link)
    tab.reveal()
    expect(tab.page.locator("#status")).to_contain_text("refuses")
    expect(tab.page.locator("#status-box")).to_have_attribute("data-tone", "err")
    expect(tab.page.locator("#password-form")).to_be_hidden()
    tab.page.wait_for_timeout(300)
    assert reveal_calls(tab) == 1  # the one that was answered, and no second one
    assert len(stored_keys(sync_redis)) == 1  # the real secret was never touched


@pytest.mark.parametrize("iterations", [MIN_ITERATIONS, MAX_ITERATIONS], ids=["min", "max"])
def test_the_limits_themselves_are_accepted(tab: Tab, iterations: int) -> None:
    link = tab.create("hello")
    server_asks_for_a_password(tab, iterations)
    tab.open_link(link)
    tab.reveal()
    expect(tab.page.locator("#password-form")).to_be_visible()
    expect(tab.page.locator("#status")).to_contain_text("needs a password")


FAIL_PBKDF2 = """
(() => {
  const original = SubtleCrypto.prototype.deriveBits;
  SubtleCrypto.prototype.deriveBits = function (algorithm, ...rest) {
    if (algorithm.name === "PBKDF2") return Promise.reject(new Error("out of memory"));
    return original.call(this, algorithm, ...rest);
  };
})();
"""


def test_a_derivation_that_fails_shows_an_error_and_sends_nothing(
    tab: Tab, sync_redis: SyncRedis
) -> None:
    link = tab.create("hello", password=PASSWORD)
    tab.page.add_init_script(FAIL_PBKDF2)  # applies to the pages opened from now on
    tab.requests.clear()
    tab.open_link(link)
    tab.reveal()
    tab.page.fill("#access-password", PASSWORD)
    tab.page.click("#open-secret")
    expect(tab.page.locator("#status")).to_contain_text("Could not check the password")
    expect(tab.page.locator("#status-box")).to_have_attribute("data-tone", "err")
    expect(tab.page.locator("#open-secret")).to_be_enabled()  # the person can try again
    assert tab.page.input_value("#access-password") == ""  # and the password is not left behind
    assert reveal_calls(tab) == 1  # only the first ask; the failed derivation sent no answer
    assert len(stored_keys(sync_redis)) == 1
