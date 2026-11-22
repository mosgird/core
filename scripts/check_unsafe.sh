#!/bin/sh
# covers: *
# Enforces the rule that `unsafe` code exists in one module only:
# crates/mosgird-core/src/secure_mem.rs. The compiler enforces the rest:
# the workspace forbids unsafe_code, and mosgird-core denies it except on
# that module.
#
# Fails if:
# - `unsafe` appears in any other Rust file (outside comments);
# - `allow(unsafe_code)` appears anywhere but on `pub mod secure_mem;`;
# - a crate other than mosgird-core relaxes the unsafe_code lint.
set -eu

allowed=crates/mosgird-core/src/secure_mem.rs
status=0

for f in $(git ls-files '*.rs'); do
    [ "$f" = "$allowed" ] && continue
    # Drop line comments, then look for the keyword.
    if sed 's://.*$::' "$f" | grep -Eqw 'unsafe'; then
        if ! sed 's://.*$::' "$f" | grep -Ew 'unsafe' | grep -Eq 'unsafe_code'; then
            echo "check_unsafe: 'unsafe' outside $allowed: $f" >&2
            status=1
        fi
    fi
done

allows=$(git grep -n 'allow(unsafe_code)' -- '*.rs' || true)
expected='crates/mosgird-core/src/lib.rs'
count=$(printf '%s\n' "$allows" | grep -c . || true)
if [ "$count" -ne 1 ] || ! printf '%s\n' "$allows" | grep -q "^$expected:"; then
    echo "check_unsafe: allow(unsafe_code) must appear once, in $expected:" >&2
    printf '%s\n' "$allows" >&2
    status=1
fi
line=$(printf '%s\n' "$allows" | cut -d: -f2)
next=$(sed -n "$((line + 1))p" "$expected")
if [ "$next" != "pub mod secure_mem;" ]; then
    echo "check_unsafe: allow(unsafe_code) must be directly on 'pub mod secure_mem;'" >&2
    status=1
fi

for toml in $(git ls-files '*/Cargo.toml' 'Cargo.toml'); do
    case "$toml" in
    crates/mosgird-core/Cargo.toml) continue ;;
    esac
    if grep -Eq '^unsafe_code *= *"(allow|warn)"' "$toml"; then
        echo "check_unsafe: $toml relaxes unsafe_code" >&2
        status=1
    fi
done

[ "$status" -eq 0 ] && echo "check_unsafe: unsafe code only in $allowed"
exit "$status"
