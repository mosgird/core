#!/bin/sh
# covers: *
# Checks that a Linux release binary carries the hardening that
# .cargo/config.toml asks for. Usage: scripts/check_hardening.sh <binary>
set -eu

bin=$1
status=0

check() {
    if eval "$2"; then
        echo "ok:      $1"
    else
        echo "MISSING: $1" >&2
        status=1
    fi
}

check "position-independent executable" \
    "readelf -hW '$bin' | grep -q 'DYN (Position-Independent Executable'"
check "full RELRO (GNU_RELRO segment and BIND_NOW)" \
    "readelf -lW '$bin' | grep -q GNU_RELRO && readelf -dW '$bin' | grep -Eq 'BIND_NOW|FLAGS_1.*NOW'"
check "non-executable stack" \
    "readelf -lW '$bin' | grep GNU_STACK | grep -qv 'RWE'"
check "stack protector" \
    "readelf -sW '$bin' | grep -q '__stack_chk_fail'"
check "symbols stripped" \
    "! readelf -SW '$bin' | grep -q '\.symtab'"

# Reported, not required: the linker sets the CET property only when
# every object, including the C runtime, has it. See README.md.
if readelf -nW "$bin" | grep -q 'IBT'; then
    echo "ok:      Intel CET (IBT, SHSTK) marked"
else
    echo "note:    Intel CET not marked; the C runtime objects may lack it"
fi

exit "$status"
