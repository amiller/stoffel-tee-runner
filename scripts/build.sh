#!/bin/bash
# Run cargo inside a memory-capped container. Use this instead of bare cargo.
# This workspace is small, but bare cargo has OOM-frozen the build hosts before
# and the cap costs nothing.
#   ./scripts/build.sh test -p lobby-records
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${CARGO_TARGET_DIR:-$HOME/cargo-targets/stoffel-tee-runner}
mkdir -p "$TARGET"
# --cpus needs the cgroup v2 cpu controller; some hosts (zed's 5.15 kernel)
# list it without enabling it, and docker then refuses to run at all. The
# memory cap is the load-bearing one — keep it either way.
CPUS=(--cpus=2)
if [ ! -f /sys/fs/cgroup/cpu.max ]; then CPUS=(); fi
exec docker run --rm --memory=6g "${CPUS[@]}" \
  -e CARGO_TARGET_DIR=/target \
  -v "$REPO":/build -v "$TARGET":/target -w /build \
  --entrypoint /bin/bash rust:1-bookworm -c "cargo $(printf '%q ' "$@")"
