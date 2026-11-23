"""The parts of the delivery that are text in a file: server flags, README and doc claims.

Each check reads the file the operator or the CI really uses, so a flag dropped from the
Dockerfile or the README command turns a test red.
"""

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
SECURITY_DOC = (ROOT / "docs" / "security.md").read_text(encoding="utf-8")


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
    assert "Every response the app produces" in SECURITY_DOC
    assert re.search(r"protocol error.{0,200}uvicorn", SECURITY_DOC, re.DOTALL)


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


def test_the_test_images_are_pinned_by_digest_and_redis_is_the_one_of_the_compose_file() -> None:
    from conftest import IMAGES

    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    redis = re.search(r"image: (redis:\S+@sha256:[0-9a-f]{64})", compose)
    assert redis, "the compose file does not pin redis by digest"
    assert IMAGES[0] == redis.group(1)
    for image in IMAGES:
        assert re.fullmatch(r"[\w./-]+:[\w.]+@sha256:[0-9a-f]{64}", image), image


def test_the_readme_says_the_test_images_are_pinned_too() -> None:
    assert re.search(r"test images.{0,80}pinned by digest", SECURITY_DOC, re.DOTALL | re.IGNORECASE)


CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def test_the_ci_runs_the_compose_smoke_as_its_own_job() -> None:
    job = re.search(r"\n  compose-smoke:\n(.*?)(?=\n  \S|\Z)", CI, re.DOTALL)
    assert job, "no compose-smoke job in the CI"
    assert "run: uv run --no-project python scripts/compose_smoke.py" in job.group(1)
    script = (ROOT / "scripts" / "compose_smoke.py").read_text(encoding="utf-8")
    assert '"up", "--build"' in script and '"--wait"' in script
    assert '"down", "--volumes"' in script


def test_every_action_of_the_ci_is_pinned_by_commit_sha() -> None:
    uses = re.findall(r"uses: (\S+)", CI)
    assert len(uses) >= 5, uses
    for action in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action), action
