"""Run the real compose.yaml and check one secret end to end, then take it all down.

Steps: `docker compose up --build --wait` (the healthchecks of compose.yaml decide when the app is
ready), create a secret through the API, read it once (200, the same bytes back), read it again
(404), and `docker compose down -v`. The server keys are made fresh for the run. The app logs are
printed when a step fails. Only the standard library is used.

Usage: uv run python scripts/compose_smoke.py
"""

import base64
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE_URL = "http://127.0.0.1:8000"
PROJECT = "otv-compose-smoke"
READY_SECONDS = 180


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def compose(*args: str, env: dict[str, str]) -> None:
    command = ["docker", "compose", "-p", PROJECT, *args]
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def post(path: str, payload: dict[str, str] | None = None) -> tuple[int, dict[str, str]]:
    data = json.dumps(payload).encode() if payload is not None else b""
    request = urllib.request.Request(
        BASE_URL + path, data=data, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, {}  # only the status of an error answer is checked


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print("ok:", message, flush=True)


def one_secret_end_to_end() -> None:
    # One 256-byte block plus the 16-byte GCM tag, as the browser sends it.
    sent = {"iv": b64(os.urandom(12)), "ciphertext": b64(os.urandom(256 + 16)), "expires_in": "1h"}
    status, created = post("/api/secrets", sent)
    check(status == 201, f"create answers 201 (got {status})")
    secret_id = created["id"]

    status, first = post(f"/api/secrets/{secret_id}/reveal")
    check(status == 200, f"first read answers 200 (got {status})")
    check(
        first == {"iv": sent["iv"], "ciphertext": sent["ciphertext"]},
        "first read returns the stored iv and ciphertext",
    )

    status, _ = post(f"/api/secrets/{secret_id}/reveal")
    check(status == 404, f"second read answers 404 (got {status})")


def main() -> int:
    env = {**os.environ, "OTV_SERVER_KEYS": f"1:{secrets.token_urlsafe(32)}"}
    try:
        compose(
            "up", "--build", "--detach", "--wait", "--wait-timeout", str(READY_SECONDS), env=env
        )
        one_secret_end_to_end()
    except (AssertionError, subprocess.CalledProcessError, OSError, KeyError) as error:
        print(f"FAILED: {error!r}", file=sys.stderr, flush=True)
        subprocess.run(["docker", "compose", "-p", PROJECT, "logs", "app"], cwd=ROOT, env=env)
        return 1
    finally:
        compose("down", "--volumes", "--rmi", "local", env=env)
    print("compose smoke: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
