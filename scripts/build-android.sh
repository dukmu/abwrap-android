#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ABI=${1:-arm64-v8a}
API=${ANDROID_API:-26}
NDK=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}

if [ -z "$NDK" ]; then
  echo "ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) is not set" >&2
  exit 2
fi
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
if [ ! -f "$TOOLCHAIN" ]; then
  echo "NDK CMake toolchain not found: $TOOLCHAIN" >&2
  exit 2
fi
case "$ABI" in
  arm64-v8a|x86_64) ;;
  *) echo "unsupported ABI: $ABI (supported: arm64-v8a, x86_64)" >&2; exit 2 ;;
esac

BUILD=${BUILD_DIR:-"$ROOT/build-android/$ABI"}
cmake -S "$ROOT" -B "$BUILD" \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM="android-$API" \
  -DANDROID_STL=none \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF \
  -DABW_ENABLE_WERROR=ON
cmake --build "$BUILD" -j"${JOBS:-2}"
printf 'built: %s/abwrap\n' "$BUILD"
