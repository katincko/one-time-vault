#!/bin/sh
# Known-vulnerability scan of the locked dependencies (all groups, the tests' too). The export
# is filtered of the editable line (this project, which is not on PyPI) and audited as it is
# locked: --no-deps and --disable-pip, so nothing is resolved or installed again.
# Usage: sh scripts/audit.sh [uv.lock directory]   (default: the repository)
set -eu
cd "${1:-$(dirname "$0")/..}"

requirements="$(mktemp)"
trap 'rm -f "$requirements"' EXIT
uv export --locked --all-groups --quiet | grep -v '^-e ' > "$requirements"
echo "pip-audit: $(grep -c '==' "$requirements") locked packages"
uvx pip-audit --no-deps --disable-pip -r "$requirements"
