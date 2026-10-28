"""The pages as designed: real radios for the expiry, no inline style, no sideways scroll."""

import json
from collections.abc import Iterator

import pytest
from playwright.sync_api import Browser, expect
from redis import Redis as SyncRedis

from browser_kit import Tab
from conftest import LiveServer

OPTIONS = [("1h", "1 hour"), ("1d", "1 day"), ("7d", "7 days")]


@pytest.fixture
def narrow(browser: Browser, live_server: LiveServer, sync_redis: SyncRedis) -> Iterator[Tab]:
    """A tab the width of a small phone."""
    context = browser.new_context(viewport={"width": 375, "height": 800})
    context.grant_permissions(["clipboard-read", "clipboard-write"])
    yield Tab(context.new_page(), live_server.url)
    context.close()


def sideways_overflow(tab: Tab) -> int:
    """Pixels by which the page is wider than the window (0 means no sideways scroll)."""
    return int(
        tab.page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
    )


def test_the_three_expiry_options_are_radios_and_the_chosen_one_is_sent(tab: Tab) -> None:
    tab.page.goto(tab.base + "/")
    radios = tab.page.locator('input[type="radio"][name="expires_in"]')
    assert [radios.nth(i).get_attribute("value") for i in range(radios.count())] == [
        v for v, _ in OPTIONS
    ]
    assert tab.page.locator('input[name="expires_in"]:checked').get_attribute("value") == "1d"
    for value, label in OPTIONS:
        tab.requests.clear()
        tab.page.get_by_text(label, exact=True).click()  # what a person clicks: the drawn option
        expect(tab.page.locator(f'input[name="expires_in"][value="{value}"]')).to_be_checked()
        tab.page.fill("#text", f"for {value}")
        tab.page.click("#create")
        expect(tab.page.locator("#result")).to_be_visible()
        posts = [r for r in tab.api_calls() if r.method == "POST"]
        assert [json.loads(r.post_data or "{}")["expires_in"] for r in posts] == [value]


def test_the_chosen_option_shows_a_mark_and_the_keyboard_moves_it(tab: Tab) -> None:
    tab.page.goto(tab.base + "/")
    checked = tab.page.locator(".opt:has(input:checked) svg")
    expect(checked).to_be_visible()
    assert tab.page.locator(".opt svg:visible").count() == 1
    tab.page.focus('input[name="expires_in"][value="1d"]')
    tab.page.keyboard.press("ArrowRight")
    expect(tab.page.locator('input[name="expires_in"][value="7d"]')).to_be_checked()
    assert tab.page.locator(".opt svg:visible").count() == 1


def test_no_element_ever_carries_a_style_attribute(tab: Tab) -> None:
    tab.page.goto(tab.base + "/")
    assert tab.page.locator("[style]").count() == 0
    tab.page.fill("#text", "x" * (10 * 1024 + 1))
    tab.page.click("#create")  # the error box
    expect(tab.page.locator("#error")).to_be_visible()
    assert tab.page.locator("[style]").count() == 0
    link = tab.create("hello", password="correct horse")
    tab.page.click("#copy")
    assert tab.page.locator("[style]").count() == 0  # the link box and the copy button
    tab.open_link(link)
    expect(tab.page.locator("#reveal")).to_be_visible()
    assert tab.page.locator("[style]").count() == 0  # "ready"
    tab.reveal()
    expect(tab.page.locator("#password-form")).to_be_visible()
    assert tab.page.locator("[style]").count() == 0  # the password form
    tab.page.fill("#access-password", "wrong")
    tab.page.click("#open-secret")
    expect(tab.page.locator("#status")).to_contain_text("Wrong password")
    assert tab.page.locator("[style]").count() == 0  # a warning tone
    tab.open_link(link.split("#")[0])
    expect(tab.page.locator("#status")).to_contain_text("Incomplete link")
    assert tab.page.locator("[style]").count() == 0


def test_the_create_page_does_not_scroll_sideways_at_375(narrow: Tab) -> None:
    narrow.page.goto(narrow.base + "/")
    assert sideways_overflow(narrow) == 0
    narrow.page.fill("#text", "x" * (10 * 1024 + 1))
    narrow.page.click("#create")
    expect(narrow.page.locator("#error")).to_be_visible()
    assert sideways_overflow(narrow) == 0
    link = narrow.create("a" * 200)  # the link and its button, in the narrow card
    assert sideways_overflow(narrow) == 0
    assert len(link) > 60
    box = narrow.page.locator(".card").bounding_box()
    assert box and box["x"] >= 0 and box["x"] + box["width"] <= 375


def test_the_open_page_does_not_scroll_sideways_at_375(narrow: Tab) -> None:
    link = narrow.create("w" * 300 + " " + "z" * 300)
    narrow.open_link(link)
    narrow.reveal()
    expect(narrow.page.locator("#secret")).to_be_visible()
    assert sideways_overflow(narrow) == 0


def test_copy_keeps_its_button_style_when_it_says_copied(narrow: Tab) -> None:
    narrow.create("hello")
    narrow.page.click("#copy")
    copy = narrow.page.locator("#copy")
    expect(copy).to_have_text("Copied")
    expect(copy).to_have_class("btn done")
