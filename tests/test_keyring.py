"""The server keys: required at boot, versioned, and the stored form of a verifier."""

import base64
import hashlib
import hmac
import os
import subprocess
import sys

import pytest

from conftest import KEY_V1, KEY_V2, SERVER_KEYS
from one_time_vault.app import app_from_env
from one_time_vault.keyring import Keyring, KeyringError, UnknownKeyVersion, iterations_of


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


VERIFIER = bytes(range(100, 132))


def test_seal_is_header_plus_hmac_of_the_verifier_under_the_current_key() -> None:
    stored = Keyring.parse(SERVER_KEYS).seal(VERIFIER, 600_000)
    assert stored[0] == 2  # the first key listed is the current one
    assert iterations_of(stored) == 600_000
    assert stored[5:] == hmac.new(KEY_V2, VERIFIER, hashlib.sha256).digest()
    assert VERIFIER not in stored


def test_bind_uses_the_key_version_the_secret_was_sealed_with() -> None:
    old = Keyring.parse(f"1:{b64(KEY_V1)}").seal(VERIFIER, 700_000)
    rotated = Keyring.parse(SERVER_KEYS)  # now version 2 is current, 1 is kept
    assert rotated.bind(old, VERIFIER) == old
    assert rotated.bind(old, b"x" * 32) != old
    assert rotated.seal(VERIFIER, 700_000)[0] == 2  # new secrets use the new key


def test_a_secret_sealed_by_a_dropped_key_is_an_error_not_a_wrong_password() -> None:
    old = Keyring.parse(f"1:{b64(KEY_V1)}").seal(VERIFIER, 600_000)
    with pytest.raises(UnknownKeyVersion):
        Keyring.parse(f"2:{b64(KEY_V2)}").bind(old, VERIFIER)


@pytest.mark.parametrize(
    "text",
    [
        None,
        "",
        "   ",
        b64(KEY_V1),  # no version
        f"1:{b64(KEY_V1[:31])}",  # 31 bytes
        f"0:{b64(KEY_V1)}",
        f"256:{b64(KEY_V1)}",
        f"1:{b64(KEY_V1)},1:{b64(KEY_V2)}",  # repeated version
        f"1:{b64(KEY_V1)},",  # empty entry
        "1:not base64!",
        f"x:{b64(KEY_V1)}",
    ],
)
def test_bad_server_keys_refuse_to_boot(text: str | None) -> None:
    with pytest.raises(KeyringError):
        Keyring.parse(text)


def test_the_app_factory_needs_the_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OTV_SERVER_KEYS", raising=False)
    with pytest.raises(KeyringError):
        app_from_env()


def test_the_real_server_process_does_not_start_without_the_keys() -> None:
    env = {k: v for k, v in os.environ.items() if k != "OTV_SERVER_KEYS"}
    proc = subprocess.run(
        [sys.executable, "-m", "uvicorn", "--factory", "one_time_vault.app:app_from_env",
         "--port", "0"],
        env=env, capture_output=True, text=True, timeout=30,
    )  # fmt: skip
    assert proc.returncode != 0
    assert "OTV_SERVER_KEYS is required" in proc.stderr
