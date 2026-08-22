#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR=${1:-"$ROOT/build-nonroot"}

cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON -DABW_ENABLE_WERROR=ON -DABW_BUILD_PYTHON_INTEGRATION=OFF
cmake --build "$BUILD_DIR" --parallel

if [[ $(id -u) -eq 0 ]]; then
  if command -v runuser >/dev/null 2>&1 && id nobody >/dev/null 2>&1; then
    runuser -u nobody -- "$BUILD_DIR/arch_unit_test"
    runuser -u nobody -- "$BUILD_DIR/policy_unit_test"
  elif command -v su >/dev/null 2>&1 && id nobody >/dev/null 2>&1; then
    su -s /bin/sh nobody -c "'$BUILD_DIR/arch_unit_test' && '$BUILD_DIR/policy_unit_test'"
  else
    echo "SKIP: no usable non-root account runner" >&2
    exit 77
  fi
else
  "$BUILD_DIR/arch_unit_test"
  "$BUILD_DIR/policy_unit_test"
fi
