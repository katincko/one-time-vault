"""The test command in the README, pasted as it is, must run the whole suite."""

import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def readme_test_command() -> str:
    """The `uv run pytest ...` command of the Tests block, continuation lines joined."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = re.search(r"## Tests\s+```\n(.*?)```", readme, re.DOTALL)
    assert block, "no code block under Tests"
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


def readme() -> str:
    return (ROOT / "README.md").read_text(encoding="utf-8")


def test_python_in_a_pasted_command_is_uv_run_python() -> None:
    """Ubuntu and Debian have no `python`: a command pasted from the docs must use `uv run`."""
    for name in ["README.md", "compose.yaml", "docs/security.md", "SECURITY.md"]:
        path = ROOT / name
        if not path.exists():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            assert not re.search(r"(?<!uv run )\bpython3? -c", line), f"{name}:{number}: {line}"


def test_compose_down_in_the_readme_runs_in_a_shell_without_the_keys() -> None:
    """compose.yaml requires OTV_SERVER_KEYS even for `down`, so the command must carry a value."""
    downs = [ln for ln in readme().splitlines() if "docker compose down" in ln]
    assert downs, "no `docker compose down` command in the README"
    assert all(ln.lstrip().startswith("OTV_SERVER_KEYS=") for ln in downs), downs


def test_the_readme_test_count_is_the_real_one() -> None:
    """`N test cases` in the README is what pytest collects now (Redis and Valkey count twice)."""
    stated = re.findall(r"\*\*(\d+) test cases\*\*", readme())
    assert len(stated) == 1, "the README must state `**N test cases**` once"
    files = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "tests").glob("test_*.py"))
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", *files],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    collected = re.search(r"(\d+) tests? collected", out.stdout)
    assert collected, out.stdout[-400:]
    assert int(stated[0]) == int(collected.group(1))


def test_the_readme_links_the_security_doc_and_the_screenshots_exist() -> None:
    text = readme()
    assert "(docs/security.md)" in text
    assert (ROOT / "docs" / "security.md").is_file()
    images = re.findall(r"\]\((docs/img/[\w.-]+\.png)\)", text)
    assert len(images) >= 2, images
    for image in images:
        assert (ROOT / image).stat().st_size > 1000, image


def test_the_security_policy_uses_the_private_advisory_form_and_has_no_email() -> None:
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "private vulnerability reporting" in policy.lower()
    assert "@" not in policy
