#!/bin/sh
# covers: *
# Runs the dudect timing test and fails if any |t| exceeds the limit.
# dudect's authors read |t| > 5 as a likely leak; the default limit of 10
# leaves room for noise on shared CI runners. Usage:
#   scripts/dudect_check.sh [limit]
set -eu

limit=${1:-10}
cd tools/dudect
cargo build --release --locked
out=$(target/release/dudect)
printf '%s\n' "$out"
printf '%s\n' "$out" | awk -v limit="$limit" '
    /max t = / {
        split($0, parts, "max t = ")
        t = parts[2] + 0
        if (t < 0) t = -t
        n++
        if (t > limit) { bad++; print "dudect: |t| = " t " is above " limit ": " $2 > "/dev/stderr" }
    }
    END {
        if (n == 0) { print "dudect: no result found" > "/dev/stderr"; exit 1 }
        if (bad > 0) exit 1
        print "dudect: all " n " tests below |t| = " limit
    }'
