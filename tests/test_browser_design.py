"""The pages as designed: real radios for the expiry, no inline style, no sideways scroll."""

import json
import re
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


@pytest.fixture
def no_js(browser: Browser, live_server: LiveServer, sync_redis: SyncRedis) -> Iterator[Tab]:
    """A tab with JavaScript switched off."""
    context = browser.new_context(java_script_enabled=False)
    yield Tab(context.new_page(), live_server.url)
    context.close()


def test_without_javascript_the_open_page_shows_only_the_error(no_js: Tab) -> None:
    no_js.page.goto(no_js.base + "/s/abc#" + "A" * 43)
    shown = no_js.page.locator(".status:visible")
    expect(shown).to_have_count(1)
    expect(shown).to_have_text("This page needs JavaScript to decrypt in your browser.")
    expect(no_js.page.locator("#status-box")).to_be_hidden()


def test_without_javascript_the_create_page_shows_only_the_error(no_js: Tab) -> None:
    no_js.page.goto(no_js.base + "/")
    shown = no_js.page.locator(".card .status:visible")
    expect(shown).to_have_count(1)
    expect(shown).to_have_text("This page needs JavaScript to encrypt in your browser.")
    for control in ("#text", "#password", "#create", ".seg"):
        expect(no_js.page.locator(control)).to_be_hidden()


def test_an_empty_secret_shows_the_status_and_sends_nothing(tab: Tab) -> None:
    tab.page.goto(tab.base + "/")
    tab.page.fill("#text", "x" * (10 * 1024 + 1))
    tab.page.click("#create")
    expect(tab.page.locator("#error-text")).to_have_text("The secret is longer than 10 KB.")
    tab.requests.clear()
    tab.page.fill("#text", "")
    tab.page.click("#create")
    expect(tab.page.locator("#error-text")).to_have_text("Write a secret first.")
    expect(tab.page.locator("#error")).to_be_visible()
    expect(tab.page.locator("#text")).to_be_focused()
    assert [r for r in tab.api_calls() if r.method == "POST"] == []


def channels(rgb: str) -> list[float]:
    return [float(n) for n in re.findall(r"[\d.]+", rgb)[:3]]


def luminance(rgb: str) -> float:
    lin = [(c / 255) / 12.92 if c / 255 <= 0.03928 else ((c / 255 + 0.055) / 1.055) ** 2.4
           for c in channels(rgb)]  # fmt: skip
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_the_border_of_every_field_has_3_to_1_in_both_themes(
    browser: Browser, live_server: LiveServer, sync_redis: SyncRedis, scheme: str
) -> None:
    context = browser.new_context(color_scheme=scheme)  # type: ignore[arg-type]
    tab = Tab(context.new_page(), live_server.url)
    tab.create("hello")  # shows the link field too
    card = tab.page.evaluate("getComputedStyle(document.querySelector('.card')).backgroundColor")
    for selector in ("#text", "#password", ".seg", "#link"):
        border, fill = tab.page.evaluate(
            """sel => { const s = getComputedStyle(document.querySelector(sel));
                        return [s.borderTopColor, s.backgroundColor]; }""",
            selector,
        )
        assert contrast(border, card) >= 3, (scheme, selector, "border on card", border, card)
        assert contrast(border, fill) >= 3, (scheme, selector, "border on its fill", border, fill)
    context.close()


def test_the_copy_button_is_reset_for_each_new_link(narrow: Tab) -> None:
    narrow.create("first")
    narrow.page.click("#copy")
    expect(narrow.page.locator("#copy")).to_have_text("Copied")
    narrow.page.fill("#text", "second")
    narrow.page.click("#create")
    expect(narrow.page.locator("#copy")).to_have_text("Copy")
    expect(narrow.page.locator("#copy")).to_have_class("btn")


def test_when_the_clipboard_fails_the_button_asks_for_ctrl_c_and_loses_the_copied_look(
    narrow: Tab,
) -> None:
    narrow.create("hello")
    narrow.page.click("#copy")
    expect(narrow.page.locator("#copy")).to_have_text("Copied")
    narrow.page.evaluate(
        "() => { navigator.clipboard.writeText = () => Promise.reject(new Error('blocked')); }"
    )
    narrow.page.click("#copy")
    copy = narrow.page.locator("#copy")
    expect(copy).to_have_text("Press Ctrl+C")
    expect(copy).to_have_class("btn")
    assert narrow.page.evaluate("copy.scrollWidth <= copy.clientWidth")  # the text is not clipped
    assert sideways_overflow(narrow) == 0


def test_the_copied_look_is_drawn_and_sets_no_style_attribute(narrow: Tab) -> None:
    narrow.create("hello")
    look = (
        "(() => { const s = getComputedStyle(copy); return [s.backgroundColor, s.boxShadow]; })()"
    )
    before = narrow.page.evaluate(look)
    narrow.page.click("#copy")
    expect(narrow.page.locator("#copy")).to_have_text("Copied")
    after = narrow.page.evaluate(look)
    assert after[0] != before[0]  # the green fill is replaced by the soft one
    assert before[1] == "none" and after[1] != "none"  # and the ring appears
    assert narrow.page.locator("[style]").count() == 0


def test_each_status_shows_exactly_the_icon_of_its_kind(tab: Tab) -> None:
    link = tab.create("hello", password="correct horse")

    def only_icon(name: str) -> None:
        box = tab.page.locator("#status-box")
        expect(box).to_have_attribute("data-icon", name)
        expect(box.locator("svg:visible")).to_have_count(1)
        expect(box.locator("svg:visible")).to_have_class(f"i-{name}")

    tab.open_link(link.split("#")[0])
    expect(tab.page.locator("#status")).to_contain_text("Incomplete link")
    only_icon("alert")
    tab.open_link(link)
    expect(tab.page.locator("#reveal")).to_be_visible()
    only_icon("info")
    tab.reveal()
    expect(tab.page.locator("#status")).to_contain_text("needs a password")
    only_icon("key")
    tab.page.fill("#access-password", "wrong")
    tab.page.click("#open-secret")
    expect(tab.page.locator("#status")).to_contain_text("Wrong password")
    only_icon("key")
    tab.page.fill("#access-password", "correct horse")
    tab.page.click("#open-secret")
    expect(tab.page.locator("#status")).to_contain_text("Secret opened")
    only_icon("check")


@pytest.mark.parametrize("width", [900, 1100, 1241, 1300, 1440])
def test_the_title_never_breaks_into_three_lines(
    browser: Browser, live_server: LiveServer, sync_redis: SyncRedis, width: int
) -> None:
    context = browser.new_context(viewport={"width": width, "height": 900})
    page = context.new_page()
    page.goto(live_server.url + "/")
    lines = page.evaluate(
        """(() => { const h = document.querySelector('.intro h1');
                    const line = parseFloat(getComputedStyle(h).lineHeight);
                    return h.getBoundingClientRect().height / line; })()"""
    )
    assert lines <= 2.01, (width, lines)
    assert (
        page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
        == 0
    )
    context.close()
