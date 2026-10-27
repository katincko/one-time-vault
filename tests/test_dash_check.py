"""The dash check (scripts/check_dashes.py) must be red on a dash and green on clean text."""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "check_dashes.py"


def run_check(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(repo)], capture_output=True, text=True, timeout=60
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "clean.md").write_text(
        "plain text, a hyphen - and a colon: fine\n", encoding="utf-8"
    )
    return tmp_path


def test_clean_text_passes(repo: Path) -> None:
    out = run_check(repo)
    assert out.returncode == 0, out.stdout


@pytest.mark.parametrize("char", [chr(0x2014), chr(0x2013)], ids=["em-dash", "en-dash"])
def test_a_dash_in_a_new_file_is_found_with_its_line(repo: Path, char: str) -> None:
    (repo / "notes.md").write_text(f"first line\nsecond {char} line\n", encoding="utf-8")
    out = run_check(repo)
    assert out.returncode == 1
    assert "notes.md:2:" in out.stdout


def test_a_dash_in_a_file_git_ignores_is_not_checked(repo: Path) -> None:
    (repo / ".gitignore").write_text("scratch.md\n", encoding="utf-8")
    (repo / "scratch.md").write_text(f"a {chr(0x2014)} b\n", encoding="utf-8")
    assert run_check(repo).returncode == 0


def test_a_binary_file_is_skipped(repo: Path) -> None:
    (repo / "blob.bin").write_bytes(b"\x00\xe2\x80\x94\x00")
    assert run_check(repo).returncode == 0
