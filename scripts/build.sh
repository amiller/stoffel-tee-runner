#!/bin/bash
# Run cargo inside a memory-capped container. Use this instead of bare cargo.
# This workspace is small, but bare cargo has OOM-frozen the build hosts before
# and the cap costs nothing.
#   ./scripts/build.sh test -p stoffel-verify
# CPU-side the cap is CARGO_BUILD_JOBS=2 rather than `--cpus`: this host's
# kernel has no CPU CFS controller, and `docker run --cpus` hard-fails on it,
# so the container-level cpu cap was doing nothing here anyway.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${CARGO_TARGET_DIR:-$HOME/cargo-targets/stoffel-tee-runner}
mkdir -p "$TARGET"
exec docker run --rm --memory=6g -e CARGO_BUILD_JOBS=2 \
  -e CARGO_TARGET_DIR=/target \
  -v "$REPO":/build -v "$TARGET":/target -w /build \
  --entrypoint /bin/bash rust:1-bookworm -c "cargo $(printf '%q ' "$@")"
