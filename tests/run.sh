#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BIN="../alosint"
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

FAILURES=0
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

pass() {
    printf "${GREEN}[PASS]${NC} %s\n" "$1"
}

fail() {
    printf "${RED}[FAIL]${NC} %s\n" "$1"
    FAILURES=$((FAILURES + 1))
}

if [ ! -x "$BIN" ]; then
    printf "${RED}[FAIL]${NC} binary not found: %s\n" "$BIN" >&2
    exit 1
fi

output="$("$BIN" --version 2>"$TMP_DIR/stderr")"
rc=$?
if [ "$rc" -eq 0 ] && [ "$output" = "alosint 1.0.0" ]; then
    pass "version"
else
    fail "version"
fi

output="$("$BIN" -d example.com 2>"$TMP_DIR/stderr")"
rc=$?
if [ "$rc" -eq 0 ] && [[ "$output" == *"resolves to"* ]]; then
    pass "dns success"
else
    fail "dns success"
fi

output="$("$BIN" -d example.com --json 2>"$TMP_DIR/stderr")"
rc=$?
if [ "$rc" -eq 0 ]; then
    if command -v jq >/dev/null 2>&1; then
        if printf '%s' "$output" | jq -e . >/dev/null 2>&1; then
            pass "json success"
        else
            fail "json success"
        fi
    elif [[ "$output" == *'{"domain":"example.com"'* ]]; then
        pass "json success"
    else
        fail "json success"
    fi
else
    fail "json success"
fi

"$BIN" --ip not-an-ip >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"
rc=$?
if [ "$rc" -eq 1 ]; then
    pass "rdap failure"
else
    fail "rdap failure"
fi

output="$("$BIN" -d example.com --quiet 2>"$TMP_DIR/stderr")"
rc=$?
if [ "$rc" -eq 0 ] && [ -z "$output" ]; then
    pass "quiet mode"
else
    fail "quiet mode"
fi

"$BIN" -d example.com --verbose >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"
rc=$?
if [ "$rc" -eq 0 ] && grep -q "\[verbose\]" "$TMP_DIR/stderr"; then
    pass "verbose"
else
    fail "verbose"
fi

if [ "$FAILURES" -ne 0 ]; then
    printf "\n%d test(s) failed.\n" "$FAILURES" >&2
    exit 1
fi

printf "\nAll tests passed.\n"
exit 0
