#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR=${1:-"$ROOT/build-termux"}
GENERATOR=${CMAKE_GENERATOR:-Ninja}
WERROR=${ABW_TERMUX_WERROR:-OFF}

if ! command -v cmake >/dev/null 2>&1; then
    echo "cmake not found; install with: pkg install cmake" >&2
    exit 2
fi
if [[ "$GENERATOR" == "Ninja" ]] && ! command -v ninja >/dev/null 2>&1; then
    echo "ninja not found; install with: pkg install ninja" >&2
    exit 2
fi

cmake -S "$ROOT" -B "$BUILD_DIR" -G "$GENERATOR" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_TESTING=ON \
    -DABW_ENABLE_WERROR="$WERROR" \
    -DABW_BUILD_PYTHON_INTEGRATION=OFF
cmake --build "$BUILD_DIR" --parallel

printf '\nBuilt Termux-native targets in %s (Werror=%s)\n' "$BUILD_DIR" "$WERROR"
printf 'Unit tests:\n'
printf '  ctest --test-dir %q --output-on-failure\n' "$BUILD_DIR"
printf 'Diagnostics:\n'
printf '  %q --build-dir %q\n' "$ROOT/tests/termux_diagnostics.sh" "$BUILD_DIR"
