#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD=${BUILD_DIR:-"$ROOT/build"}
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTING=ON
cmake --build "$BUILD" -j"${JOBS:-2}"
ctest --test-dir "$BUILD" --output-on-failure
