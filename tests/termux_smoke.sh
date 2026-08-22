#!/data/data/com.termux/files/usr/bin/sh
set -eu

AB=${ABWRAP_BIN:-./build-termux/abwrap}
PREFIX=${PREFIX:-/data/data/com.termux/files/usr}
PY=${PYTHON:-$PREFIX/bin/python}
SH=${SHELL_BIN:-$PREFIX/bin/bash}
LS=${LS_BIN:-$PREFIX/bin/ls}
RAW=${RAW_OPEN_BIN:-$(dirname "$AB")/raw_open_test}
TMP_BASE=${TMPDIR:-$PREFIX/tmp}

[ -x "$AB" ] || { echo "missing abwrap: $AB" >&2; exit 2; }
[ -x "$SH" ] || { echo "missing bash: $SH" >&2; exit 2; }
[ -x "$PY" ] || { echo "missing python: $PY" >&2; exit 2; }

mkdir -p "$TMP_BASE"
TD=$(mktemp -d "$TMP_BASE/abwrap-smoke.XXXXXX")
trap 'rm -rf "$TD"' EXIT INT TERM
mkdir -p "$TD/rw" "$TD/ro"
printf 'value = 42\n' > "$TD/rw/mymod.py"
printf 'value = 42\n' > "$TD/ro/mymod.py"

# Android may deny app UIDs access to /. Preserve host behavior instead of
# assuming root enumeration is available.
set +e
"$LS" / >/dev/null 2>&1
host_root_rc=$?
"$AB" --ro-bind / / -- "$LS" / >/dev/null 2>&1
sandbox_root_rc=$?
set -e
[ "$sandbox_root_rc" -eq "$host_root_rc" ] || {
  echo "root access parity failed: host=$host_root_rc sandbox=$sandbox_root_rc" >&2
  exit 20
}

# A Termux-owned source is the positive RO-directory-listing test.
"$AB" --ro-bind / / --ro-bind "$PREFIX" /abwrap-prefix -- "$LS" /abwrap-prefix >/dev/null

# Bash must start in the common Termux base profile.
"$AB" --android-base -- "$SH" -c 'printf abwrap-bash-ok' | grep -q abwrap-bash-ok

# Direct raw syscall denial must also leave the host file unchanged.
if [ -x "$RAW" ]; then
  printf 'original\n' > "$TD/ro/raw.txt"
  set +e
  "$AB" --ro-bind / / --ro-bind "$TD/ro" /work -- "$RAW" write /work/raw.txt >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 30 ] || { echo "raw RO denial returned $rc, expected 30" >&2; exit 21; }
  [ "$(cat "$TD/ro/raw.txt")" = original ] || { echo "raw RO denial mutated host file" >&2; exit 22; }
fi

# RW Python module path must be allowed to create bytecode cache.
"$AB" --android-base --bind "$TD/rw" /work --setenv PYTHONPATH /work -- \
  "$PY" -c 'import mymod; assert mymod.value == 42'
ls "$TD/rw"/__pycache__/mymod*.pyc >/dev/null

# RO Python module path must still import successfully, while remaining RO.
"$AB" --android-base --ro-bind "$TD/ro" /work --setenv PYTHONPATH /work -- \
  "$PY" -c 'import mymod; assert mymod.value == 42'
[ ! -e "$TD/ro/__pycache__" ]

printf 'termux smoke: PASS\n'
