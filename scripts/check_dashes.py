"""Fail when a file of the repository holds an em dash (U+2014) or an en dash (U+2013).

Checks every file git knows (tracked, or new and not ignored), so a dash planted in a file that
is not committed yet is caught too. The dashes are written as code points, so this file stays clean.

Usage: python scripts/check_dashes.py [repository root]
"""

import subprocess
import sys
from pathlib import Path

FORBIDDEN = {chr(0x2014): "em dash (U+2014)", chr(0x2013): "en dash (U+2013)"}


def repository_files(root: Path) -> list[Path]:
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    names = sorted({n for n in listing.decode("utf-8").split("\0") if n})
    return [root / n for n in names if (root / n).is_file()]


def find_dashes(root: Path) -> list[str]:
    """One `path:line: name` entry per offending line and dash."""
    found: list[str] = []
    for path in repository_files(root):
        raw = path.read_bytes()
        if b"\0" in raw:  # binary
            continue
        text = raw.decode("utf-8", errors="replace")
        for number, line in enumerate(text.split("\n"), start=1):
            for char, name in FORBIDDEN.items():
                if char in line:
                    found.append(f"{path.relative_to(root).as_posix()}:{number}: {name}")
    return found


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    found = find_dashes(root)
    for entry in found:
        print(entry)
    if found:
        print(f"{len(found)} dash(es) found; use a comma, a colon or a plain hyphen")
        return 1
    print("no em dash or en dash in the repository")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
