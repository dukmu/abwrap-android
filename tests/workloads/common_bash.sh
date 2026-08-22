#!/usr/bin/env bash
set -euo pipefail

: "${ABW_TEST_RW:?missing ABW_TEST_RW}"
: "${ABW_TEST_RO:?missing ABW_TEST_RO}"
: "${ABW_TEST_TMP:?missing ABW_TEST_TMP}"
: "${ABW_TEST_BASH:?missing ABW_TEST_BASH}"

printf 'bash-workload: start\n'

# Read/list a read-only tree.
test "$(cat "$ABW_TEST_RO/input.txt")" = "ro-input"
ls -la "$ABW_TEST_RO" >/dev/null
find "$ABW_TEST_RO" -maxdepth 1 -type f -name input.txt | grep -q input.txt

# Normal shell language behavior: arrays/functions/loop/subshell/command substitution.
nums=(1 2 3 4)
sum=0
for n in "${nums[@]}"; do ((sum += n)); done
test "$sum" -eq 10
say() { printf '%s' "$1"; }
test "$(say function-ok)" = "function-ok"
test "$( (printf subshell-ok) )" = "subshell-ok"

# Pipes and external commands.
test "$(printf 'abc\n' | tr 'a-z' 'A-Z')" = "ABC"
test "$(printf 'alpha\nbeta\n' | grep beta)" = "beta"

# Writable filesystem behavior.
mkdir -p "$ABW_TEST_RW/tree/a"
printf 'one\n' > "$ABW_TEST_RW/tree/a/file.txt"
printf 'two\n' >> "$ABW_TEST_RW/tree/a/file.txt"
grep -q '^two$' "$ABW_TEST_RW/tree/a/file.txt"
cp "$ABW_TEST_RW/tree/a/file.txt" "$ABW_TEST_RW/tree/copy.txt"
mv "$ABW_TEST_RW/tree/copy.txt" "$ABW_TEST_RW/tree/moved.txt"
ln -s tree/moved.txt "$ABW_TEST_RW/link.txt"
test "$(readlink "$ABW_TEST_RW/link.txt")" = "tree/moved.txt"
test "$(cat "$ABW_TEST_RW/link.txt" | tail -n 1)" = "two"

# Source a generated script and launch a child bash.
cat > "$ABW_TEST_RW/lib.sh" <<'EOS'
loaded_value=source-ok
EOS
# shellcheck disable=SC1090
source "$ABW_TEST_RW/lib.sh"
test "$loaded_value" = "source-ok"
test "$("$ABW_TEST_BASH" -c 'printf child-bash-ok')" = "child-bash-ok"

# tmp-style workload.
tmpfile=$(mktemp "$ABW_TEST_TMP/bash.XXXXXX")
printf 'temporary\n' > "$tmpfile"
test "$(cat "$tmpfile")" = "temporary"
rm -f "$tmpfile"

# RO mutation must fail while reads/listing continue to work.
if (printf 'bad\n' > "$ABW_TEST_RO/should-not-exist") 2>/dev/null; then
    echo 'bash-workload: RO write unexpectedly succeeded' >&2
    exit 41
fi
if mkdir "$ABW_TEST_RO/should-not-mkdir" 2>/dev/null; then
    echo 'bash-workload: RO mkdir unexpectedly succeeded' >&2
    exit 42
fi

printf 'bash-workload: PASS\n'
