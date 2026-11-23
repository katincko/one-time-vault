"""Regenerate the README screenshots in docs/img from the real app.

Starts a throwaway Redis container, the real server on a free port, and drives Chromium through
the real flow. The secret shown is made-up text. Needs Docker and `uv run playwright install
chromium`.

Usage: uv run python scripts/screenshots.py
"""

import base64
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
from playwright.sync_api import Browser, expect, sync_playwright
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "img"
SECRET = "staging db password: example-only-not-a-real-secret"


def redis_image() -> str:
    """The image compose.yaml runs, so the pictures come from the supported setup."""
    compose = (ROOT / "compose.yaml").read_text()
    match = re.search(r"image: (redis:\S+@sha256:[0-9a-f]{64})", compose)
    assert match, "compose.yaml does not pin redis by digest"
    return match.group(1)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_until_up(url: str, proc: subprocess.Popen[bytes]) -> None:
    deadline = time.time() + 30
    while True:
        try:
            httpx.get(url + "/", timeout=1).raise_for_status()
            return
        except httpx.HTTPError:
            assert proc.poll() is None and time.time() < deadline, "server did not start"
            time.sleep(0.2)


def shoot(browser: Browser, base: str) -> None:
    desktop = browser.new_context(viewport={"width": 960, "height": 640})
    page = desktop.new_page()
    page.goto(base + "/")
    page.fill("#text", SECRET)
    page.click("#create")
    expect(page.locator("#result")).to_be_visible()
    page.screenshot(path=OUT / "1-create.png")
    link = page.input_value("#link")
    reader = desktop.new_page()
    reader.goto(link)
    reader.click("#reveal")
    expect(reader.locator("#secret")).to_be_visible()
    reader.set_viewport_size({"width": 960, "height": 320})
    reader.screenshot(path=OUT / "2-reveal.png")
    desktop.close()

    phone = browser.new_context(
        viewport={"width": 390, "height": 760}, color_scheme="dark", device_scale_factor=2
    )
    page = phone.new_page()
    page.goto(base + "/")
    page.fill("#text", SECRET)
    page.click("#create")
    expect(page.locator("#result")).to_be_visible()
    page.screenshot(path=OUT / "3-phone-dark.png")
    phone.close()


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    redis = (
        DockerContainer(redis_image())
        .with_exposed_ports(6379)
        .waiting_for(LogMessageWaitStrategy("Ready to accept connections"))
    )
    with redis:
        redis_url = f"redis://{redis.get_container_host_ip()}:{redis.get_exposed_port(6379)}"
        key = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        env = {**os.environ, "OTV_REDIS_URL": redis_url, "OTV_SERVER_KEYS": f"1:{key}"}
        port = free_port()
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "--factory", "one_time_vault.app:app_from_env"]
            + ["--host", "127.0.0.1", "--port", str(port), "--no-proxy-headers"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        base = f"http://127.0.0.1:{port}"
        try:
            wait_until_up(base, proc)
            with sync_playwright() as p:
                browser = p.chromium.launch()
                shoot(browser, base)
                browser.close()
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    print("wrote", *sorted(f.name for f in OUT.glob("*.png")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
