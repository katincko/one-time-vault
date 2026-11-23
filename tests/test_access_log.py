"""The access log of the real server process never holds a secret id.

The ids are the only handle on a secret, and `security.py` says they never go to a log. The real
server runs under uvicorn, whose access log writes the request line, so this test goes through
that process: it creates, opens and reveals a secret, then searches the captured log.
"""

import base64
import logging
import os
import socket
import time
from urllib.parse import urlsplit

import httpx
import pytest

from conftest import LiveServer
from one_time_vault.security import AccessLogMask


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_the_server_log_never_holds_the_id_of_a_secret(live_server: LiveServer) -> None:
    body = {
        "iv": b64url(os.urandom(12)),
        "ciphertext": b64url(os.urandom(256 + 16)),
        "expires_in": "1h",
    }
    with httpx.Client(base_url=live_server.url) as client:
        created = client.post("/api/secrets", json=body)
        assert created.status_code == 201
        secret_id = created.json()["id"]
        assert client.get(f"/s/{secret_id}").status_code == 200
        assert client.post(f"/api/secrets/{secret_id}/reveal").status_code == 200
        assert client.get(f"/s/{secret_id}").status_code == 200  # the page needs no storage

    deadline = time.time() + 10
    while b"/reveal" not in live_server.log() and time.time() < deadline:
        time.sleep(0.1)
    log = live_server.log()
    # The access log is on, and it says what happened, only without the id.
    assert b"GET /s/<id> HTTP/1.1" in log
    assert b"POST /api/secrets/<id>/reveal HTTP/1.1" in log
    assert secret_id.encode() not in log


@pytest.mark.parametrize(
    "shape",
    [
        "//s/{id}",
        "/api/./secrets/{id}",
        "/x/../s/{id}",
        "/s/%2F{id}",
        "/s/./{id}",
        "/api//secrets/{id}/reveal",
        "/s/%61{id}%2e",
        "/x?next={id}",
    ],
)
def test_the_server_log_never_holds_the_id_in_any_form_of_path(
    live_server: LiveServer, shape: str
) -> None:
    secret_id = b64url(os.urandom(16))
    marker = f"/marker-{secret_id[:6]}"  # proves this very request reached the log
    target = shape.format(id=secret_id)
    host = urlsplit(live_server.url)
    # A raw socket: no client normalizes the path (the dots and slashes reach the server).
    for path in (target, marker):
        with socket.create_connection((host.hostname or "", host.port or 80), timeout=10) as sock:
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
            while sock.recv(4096):
                pass
    deadline = time.time() + 10
    while marker.encode() not in live_server.log() and time.time() < deadline:
        time.sleep(0.1)
    log = live_server.log()
    assert marker.encode() in log
    assert secret_id.encode() not in log


def test_a_record_of_an_unexpected_shape_is_dropped_and_reported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    odd = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "%s", ("/s/SECRETID",), None)
    with caplog.at_level(logging.WARNING, logger="one_time_vault.security"):
        assert AccessLogMask().filter(odd) is False
    assert "access log record dropped" in caplog.text
    assert "SECRETID" not in caplog.text
