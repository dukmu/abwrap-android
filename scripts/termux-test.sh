#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR=${1:-"$ROOT/build-termux"}
"$ROOT/scripts/build-termux-native.sh" "$BUILD_DIR"
exec "$ROOT/tests/termux_diagnostics.sh" --build-dir "$BUILD_DIR"
