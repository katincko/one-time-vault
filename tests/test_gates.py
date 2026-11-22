"""The parts of the delivery that are text in a file: server flags, the README's claims.

Each check reads the file the operator or the CI really uses, so a flag dropped from the
Dockerfile or the README command turns a test red.
"""

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def readme_uvicorn_command() -> str:
    lines = [ln for ln in README.splitlines() if ln.startswith("uv run uvicorn")]
    assert len(lines) == 1, lines
    return lines[0]


def dockerfile_command() -> str:
    cmd = re.search(r"^CMD (\[.*\])$", DOCKERFILE, re.MULTILINE)
    assert cmd, "no CMD in the Dockerfile"
    return cmd.group(1)


def test_uvicorn_does_not_name_itself_in_the_image_or_in_the_readme_command() -> None:
    assert '"--no-server-header"' in dockerfile_command()
    assert "--no-server-header" in readme_uvicorn_command().split()


def test_the_readme_claims_the_headers_only_for_what_the_app_produces() -> None:
    assert "Every response the app produces" in README
    assert re.search(r"protocol error.{0,200}uvicorn", README, re.DOTALL)


def test_the_dependency_audit_is_a_step_of_make_verify_and_of_the_ci() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    verify = makefile.split("verify:", 1)[1]
    assert "\tsh scripts/audit.sh\n" in verify
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert re.search(r"- name: Dependency audit\n\s+run: sh scripts/audit.sh\n", ci)


def test_the_audit_script_audits_the_locked_set_without_the_editable_project() -> None:
    script = (ROOT / "scripts" / "audit.sh").read_text(encoding="utf-8")
    assert "uv export --locked --all-groups" in script
    assert "grep -v '^-e '" in script
    assert "uvx pip-audit --no-deps --disable-pip -r" in script
