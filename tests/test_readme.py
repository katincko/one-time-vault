"""The test command in the README, pasted as it is, must run the whole suite."""

import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def readme_test_command() -> str:
    """The `uv run pytest ...` command of the Develop block, continuation lines joined."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = re.search(r"## Develop\s+```\n(.*?)```", readme, re.DOTALL)
    assert block, "no code block under Develop"
    joined = block.group(1).replace("\r\n", "\n").replace("\\" + "\n", " ")
    lines = [ln for ln in joined.split("\n") if ln.startswith("uv run pytest")]
    assert len(lines) == 1, lines
    return lines[0]


def test_the_command_has_no_literal_backslash_n() -> None:
    backslash = chr(92)
    assert backslash + "n" not in readme_test_command()


def test_the_command_names_every_test_file_once() -> None:
    args = shlex.split(readme_test_command())
    named = [a for a in args if a.startswith("tests/")]
    on_disk = sorted(f"tests/{p.name}" for p in (ROOT / "tests").glob("test_*.py"))
    assert sorted(named) == on_disk, "the README command and tests/ disagree"


def test_the_pasted_command_collects_every_test_without_error() -> None:
    args = shlex.split(readme_test_command())
    assert args[:3] == ["uv", "run", "pytest"]
    tail = [a for a in args[3:] if a != "-q"]
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", *tail],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert out.returncode == 0, out.stdout[-800:] + out.stderr[-800:]
    assert "no tests ran" not in out.stdout
    assert "ERROR" not in out.stdout
