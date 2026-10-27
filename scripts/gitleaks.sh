#!/bin/sh
# Secret scan, two passes: every commit of the history, then the working tree (so a secret is
# caught before it is committed). gitleaks v8.30.1 runs from its image, pinned by digest.
set -eu
cd "$(dirname "$0")/.."

IMAGE="ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

run() {
  # MSYS_NO_PATHCONV: Git Bash on Windows must not rewrite /repo. The safe.directory variables
  # let git inside the container read a checkout owned by another user.
  MSYS_NO_PATHCONV=1 docker run --rm \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo \
    -v "$PWD:/repo:ro" -w /repo "$IMAGE" "$@"
}

echo "gitleaks: history"
run git --config /repo/.gitleaks.toml --redact --no-banner --verbose /repo
echo "gitleaks: working tree"
run dir --config /repo/.gitleaks.toml --redact --no-banner --verbose /repo
