#!/bin/sh
# covers: *
# Constant-time check under Valgrind. See tools/ct-check/src/main.rs.
#
# Fails if Memcheck reports a branch or an address that depends on a
# secret anywhere in this workspace's code, and fails if the negative
# control (a function that leaks on purpose) is not caught.
#
# Only errors with a frame in our code count. The C library may report
# its own startup reads, notably in a static build, and those do not
# touch secrets.
#
# Usage: scripts/ct_check.sh [path-to-ct-check-binary]
set -eu

bin=${1:-target/ct/ct-check}
log=$(mktemp)
trap 'rm -f "$log"' EXIT

ours='(mosgird_|ct_check|base32\.rs|secure_mem\.rs|lib\.rs)'

valgrind --error-exitcode=0 --num-callers=30 "$bin" 2>"$log"
if grep -Eq "^==[0-9]+== +(at|by) .*$ours" "$log"; then
    echo "ct-check: a secret-dependent branch or address was found:" >&2
    cat "$log" >&2
    exit 1
fi
echo "ct-check: no secret-dependent branch or address in our code"

valgrind --error-exitcode=0 --num-callers=30 "$bin" --negative-control 2>"$log"
if ! grep -Eq "^==[0-9]+== +(at|by) .*negative_control" "$log"; then
    echo "ct-check: the negative control was not caught; the check is not working" >&2
    cat "$log" >&2
    exit 1
fi
echo "ct-check: negative control caught, as it must be"
