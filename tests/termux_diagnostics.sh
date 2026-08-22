#!/usr/bin/env bash
# Termux/Android end-to-end diagnostics for abwrap.
# Produces one self-contained log suitable for sending back with bug reports.
set -uo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR="$ROOT/build-termux"
BACKEND_MODE=all
LOG_FILE=""

usage() {
    cat <<USAGE
Usage: $0 [--build-dir DIR] [--backend all|auto|seccomp|ptrace] [--log FILE]

Runs native CTest unit tests plus real Bash/Python workloads under abwrap.
The output is mirrored to a single diagnostics log.
USAGE
}

while (($#)); do
    case "$1" in
        --build-dir) BUILD_DIR=${2:?missing DIR}; shift 2 ;;
        --backend) BACKEND_MODE=${2:?missing backend}; shift 2 ;;
        --log) LOG_FILE=${2:?missing FILE}; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$BACKEND_MODE" in
    all) BACKENDS=(auto seccomp ptrace) ;;
    auto|seccomp|ptrace) BACKENDS=("$BACKEND_MODE") ;;
    *) echo "invalid --backend: $BACKEND_MODE" >&2; exit 2 ;;
esac

if [[ "$BUILD_DIR" != /* ]]; then
    BUILD_DIR="$(cd -- "$(dirname -- "$BUILD_DIR")" 2>/dev/null && pwd)/$(basename -- "$BUILD_DIR")"
fi

PREFIX=${PREFIX:-/data/data/com.termux/files/usr}
TMP_BASE=${TMPDIR:-$PREFIX/tmp}
PY=${PYTHON:-$PREFIX/bin/python}
BASH_BIN=${BASH_BIN:-$PREFIX/bin/bash}
ECHO_BIN=${ECHO_BIN:-$PREFIX/bin/echo}
LS_BIN=${LS_BIN:-$PREFIX/bin/ls}
AB="$BUILD_DIR/abwrap"
RAW="$BUILD_DIR/raw_open_test"
OPENAT="$BUILD_DIR/openat_probe_test"
FS_PROBE="$BUILD_DIR/fs_probe_test"

mkdir -p "$ROOT/logs" "$TMP_BASE" 2>/dev/null || true
if [[ -z "$LOG_FILE" ]]; then
    LOG_FILE="$ROOT/logs/termux-diagnostics-$(date +%Y%m%d-%H%M%S).log"
fi
mkdir -p "$(dirname -- "$LOG_FILE")"
: > "$LOG_FILE" || { echo "cannot create log: $LOG_FILE" >&2; exit 2; }
exec > >(tee -a "$LOG_FILE") 2>&1

PASS=0
FAIL=0
SKIP=0
CASE_TMP=$(mktemp -d "$TMP_BASE/abwrap-diag.XXXXXX") || exit 2
trap 'rm -rf "$CASE_TMP"' EXIT INT TERM

quote_cmd() {
    printf '  $'
    printf ' %q' "$@"
    printf '\n'
}

pass() { printf '[PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '[FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }
skip() { printf '[SKIP] %s\n' "$1"; SKIP=$((SKIP + 1)); }

run_case() {
    local label=$1 expected=$2
    shift 2
    local out="$CASE_TMP/case.out"
    : > "$out"
    printf '\n===== CASE: %s =====\n' "$label"
    quote_cmd "$@"
    "$@" >"$out" 2>&1
    local rc=$?
    cat "$out"
    printf '[exit=%d expected=%s]\n' "$rc" "$expected"
    case "$expected" in
        0) [[ $rc -eq 0 ]] && pass "$label" || fail "$label" ;;
        nonzero) [[ $rc -ne 0 ]] && pass "$label" || fail "$label" ;;
        *) [[ $rc -eq $expected ]] && pass "$label" || fail "$label" ;;
    esac
}

run_no_procfd_warning() {
    local label=$1
    shift
    local out="$CASE_TMP/case.out"
    : > "$out"
    printf '\n===== CASE: %s =====\n' "$label"
    quote_cmd "$@"
    "$@" >"$out" 2>&1
    local rc=$?
    cat "$out"
    local fdwarn=0
    if grep -E 'readlink\("/proc/self/fd/[0-9]+".*(failed|No such file)' "$out" >/dev/null 2>&1; then
        fdwarn=1
    fi
    printf '[exit=%d procfd-linker-warning=%d]\n' "$rc" "$fdwarn"
    if [[ $rc -eq 0 && $fdwarn -eq 0 ]]; then pass "$label"; else fail "$label"; fi
}

printf 'abwrap Termux diagnostics\n'
printf '==========================\n'
printf 'timestamp: %s\n' "$(date -Iseconds 2>/dev/null || date)"
printf 'repo: %s\n' "$ROOT"
printf 'build_dir: %s\n' "$BUILD_DIR"
printf 'log: %s\n' "$LOG_FILE"
printf 'requested_backends: %s\n' "${BACKENDS[*]}"
printf '\n-- sanitized platform info --\n'
printf 'uname: '; uname -a 2>&1 || true
if command -v getprop >/dev/null 2>&1; then
    printf 'android.release: '; getprop ro.build.version.release 2>/dev/null || true
    printf 'android.sdk: '; getprop ro.build.version.sdk 2>/dev/null || true
    printf 'android.abi: '; getprop ro.product.cpu.abi 2>/dev/null || true
fi
printf 'PREFIX: %s\n' "$PREFIX"
printf 'TMPDIR: %s\n' "${TMPDIR:-<unset>}"
printf 'identity: '; id 2>&1 || true
printf 'umask: '; umask 2>/dev/null || true
printf 'shell: '; "$BASH_BIN" --version 2>/dev/null | head -n 1 || true
printf 'python: '; "$PY" --version 2>&1 || true
printf 'cmake: '; cmake --version 2>/dev/null | head -n 1 || true
printf 'clang: '; clang --version 2>/dev/null | head -n 1 || true
printf 'abwrap: '; "$AB" --version 2>&1 || true

printf '\n===== PREFLIGHT: writable state directory =====\n'
STATE_PROBE="$CASE_TMP/state-probe"
if mkdir "$STATE_PROBE" 2>/dev/null && : > "$STATE_PROBE/write-test" 2>/dev/null; then
    stat -c 'mode=%a uid=%u gid=%g path=%n' "$STATE_PROBE" 2>/dev/null || ls -ld "$STATE_PROBE" 2>/dev/null || true
    pass "state-dir-writable"
else
    fail "state-dir-writable"
fi

missing=0
for f in "$AB" "$RAW" "$OPENAT" "$FS_PROBE" "$BASH_BIN" "$PY" "$ECHO_BIN" "$LS_BIN"; do
    if [[ ! -x "$f" ]]; then echo "missing executable: $f"; missing=1; fi
done
if [[ $missing -ne 0 ]]; then
    echo "Build tests first with: $ROOT/scripts/build-termux-native.sh '$BUILD_DIR'"
    exit 2
fi

printf '\n===== CTEST: native unit tests =====\n'
quote_cmd ctest --test-dir "$BUILD_DIR" --output-on-failure
ctest --test-dir "$BUILD_DIR" --output-on-failure
ct_rc=$?
if [[ $ct_rc -eq 0 ]]; then pass "ctest-native-units"; else fail "ctest-native-units"; fi

# Direct unit binaries make failures visible even if a device has an unusual CTest setup.
run_case "arch-unit-direct" 0 "$BUILD_DIR/arch_unit_test"
run_case "policy-unit-direct" 0 "$BUILD_DIR/policy_unit_test"

printf '\n===== PREFLIGHT: host root access parity =====\n'
HOST_ROOT_OUT="$CASE_TMP/host-root-ls.out"
"$LS_BIN" / >"$HOST_ROOT_OUT" 2>&1
HOST_ROOT_LS_RC=$?
cat "$HOST_ROOT_OUT"
printf '[host-ls-root-exit=%d]\n' "$HOST_ROOT_LS_RC"
pass "host-root-access-observed"

for backend in "${BACKENDS[@]}"; do
    TD="$CASE_TMP/$backend"
    mkdir -p "$TD/rw" "$TD/ro" "$TD/tmp"
    printf 'ro-input' > "$TD/ro/input.txt"
    printf 'VALUE = 456\n' > "$TD/ro/romod.py"

    base=("$AB" --backend "$backend" --ro-bind / /)

    run_no_procfd_warning "$backend: android-linker-procfd" \
        "${base[@]}" -- "$ECHO_BIN" ok

    # Android may legitimately deny enumeration of /. The sandbox must preserve
    # the caller's host permission result rather than inventing broader access.
    run_case "$backend: root-ls-host-parity" "$HOST_ROOT_LS_RC" \
        "${base[@]}" -- "$LS_BIN" /

    # Use a Termux-owned directory to verify that RO directory enumeration itself
    # works independently of Android's host-root restrictions.
    run_case "$backend: prefix-ro-ls" 0 \
        "${base[@]}" --ro-bind "$PREFIX" /abwrap-prefix -- "$LS_BIN" /abwrap-prefix

    run_case "$backend: proc-self-fd" 0 \
        "${base[@]}" -- "$BASH_BIN" -c \
        'exec 3<"$1"; readlink /proc/self/fd/3' _ "$BASH_BIN"

    run_case "$backend: proc-openat-dirfd" 0 \
        "${base[@]}" -- "$OPENAT" /proc/self status

    # A raw direct syscall must not bypass RO semantics. Verify both the tracee
    # result and the host file immediately so a false EROFS cannot hide a real write.
    printf 'original\n' > "$TD/ro/raw.txt"
    run_case "$backend: raw-open-ro-denied" 30 \
        "${base[@]}" --ro-bind "$TD/ro" /abwrap-ro -- \
        "$RAW" write /abwrap-ro/raw.txt
    if [[ "$(cat "$TD/ro/raw.txt")" == "original" ]]; then
        pass "$backend: raw-open-host-integrity"
    else
        printf '[host-content-after-denied-open]\n'
        cat "$TD/ro/raw.txt" 2>/dev/null || true
        fail "$backend: raw-open-host-integrity"
    fi

    common=("${base[@]}"
            --bind "$TD/rw" /abwrap-rw
            --ro-bind "$TD/ro" /abwrap-ro
            --bind "$TD/tmp" /abwrap-tmp
            --setenv ABW_TEST_RW /abwrap-rw
            --setenv ABW_TEST_RO /abwrap-ro
            --setenv ABW_TEST_TMP /abwrap-tmp
            --setenv ABW_TEST_BASH "$BASH_BIN")

    rm -f "$TD/ro/should-not-exist"
    rm -rf "$TD/ro/should-not-mkdir"
    run_case "$backend: common-bash-script" 0 \
        "${common[@]}" -- "$BASH_BIN" "$ROOT/tests/workloads/common_bash.sh"
    if [[ ! -e "$TD/ro/should-not-exist" && ! -e "$TD/ro/should-not-mkdir" ]]; then
        pass "$backend: bash-ro-host-integrity"
    else
        find "$TD/ro" -maxdepth 1 -name 'should-not-*' -print 2>/dev/null || true
        fail "$backend: bash-ro-host-integrity"
    fi

    pybase=("${common[@]}" --unsetenv PYTHONDONTWRITEBYTECODE --unsetenv PYTHONPYCACHEPREFIX)

    run_case "$backend: python-stdlib" 0 \
        "${pybase[@]}" -- "$PY" "$ROOT/tests/workloads/common_python.py" stdlib

    rm -f "$TD/ro/python-write-test"
    run_case "$backend: python-fs" 0 \
        "${pybase[@]}" -- "$PY" "$ROOT/tests/workloads/common_python.py" fs
    if [[ ! -e "$TD/ro/python-write-test" ]]; then
        pass "$backend: python-ro-host-integrity"
    else
        fail "$backend: python-ro-host-integrity"
    fi

    run_case "$backend: python-procfd" 0 \
        "${pybase[@]}" -- "$PY" "$ROOT/tests/workloads/common_python.py" procfd

    rm -rf "$TD/rw/__pycache__"
    run_case "$backend: python-bytecode-rw" 0 \
        "${pybase[@]}" -- "$PY" "$ROOT/tests/workloads/common_python.py" bytecode-rw
    if compgen -G "$TD/rw/__pycache__/rwmod*.pyc" >/dev/null; then
        pass "$backend: python-rw-bytecode-created"
    else
        fail "$backend: python-rw-bytecode-created"
    fi

    rm -rf "$TD/ro/__pycache__"
    run_case "$backend: python-bytecode-ro" 0 \
        "${pybase[@]}" -- "$PY" "$ROOT/tests/workloads/common_python.py" bytecode-ro
    if [[ ! -e "$TD/ro/__pycache__" ]]; then
        pass "$backend: python-ro-bytecode-not-created"
    else
        fail "$backend: python-ro-bytecode-not-created"
        find "$TD/ro/__pycache__" -maxdepth 1 -type f -print 2>/dev/null || true
    fi

    run_case "$backend: python-subprocess" 0 \
        "${pybase[@]}" -- "$PY" "$ROOT/tests/workloads/common_python.py" subprocess

    # Keep one aggregate real-world script run after the isolated cases. A failure
    # here no longer masks which Python subsystem was responsible.
    run_case "$backend: common-python-script" 0 \
        "${pybase[@]}" -- "$PY" "$ROOT/tests/workloads/common_python.py" all
done

printf '\n===== SUMMARY =====\n'
printf 'PASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
printf 'LOG=%s\n' "$LOG_FILE"
printf 'Please send this log file unchanged when reporting the result.\n'

[[ $FAIL -eq 0 ]]
