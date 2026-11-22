# Mosgird core

The shared Rust library of the Mosgird protocol. The desktop client ([mosgird/client](https://github.com/mosgird/client)) and the Android app ([mosgird/android](https://github.com/mosgird/android)) are built on it. The specification is in [mosgird/protocols](https://github.com/mosgird/protocols).

**Status:** skeleton. It contains the secret types, locked memory, and one verified piece of protocol code: the base32 encoding of addresses and invite links. No cryptographic primitive is wrapped yet. The protocol models of decision 0013 are still drafts awaiting expert review, and the cryptographic code waits for that review.

**License:** Mulan Permissive Software License, Version 2 (Mulan PSL v2). See [LICENSE.md](LICENSE.md).

## Specification

This repository implements [mosgird/protocols](https://github.com/mosgird/protocols). When the two disagree, the specification wins, and the difference is a bug to fix here or a change to propose there. Wire formats are defined in the specification first and implemented here second. For example, the layout of the invite link (decision 0014) is not implemented, because the specification text for it is not written yet.

## Layout

The workspace is split by how strongly each part is verified.

| Crate | What it holds | Rules |
|---|---|---|
| [`mosgird-protocol`](crates/mosgird-protocol) | Wire formats and state machines. No I/O, no allocation, no primitives of its own. | `no_std`, no `unsafe`, the subset of Rust that hax extracts. Extracted to F*, proved with Kani, fuzzed. |
| [`mosgird-crypto`](crates/mosgird-crypto) | Secret types; later, wrappers around the verified primitives (libcrux, with libsodium as fallback, decision 0013). | `no_std`, no `unsafe`. |
| [`mosgird-core`](crates/mosgird-core) | Locked memory now; later storage (decision 0015), transports (decision 0009), and the interface to the apps. | `unsafe` only in [`secure_mem`](crates/mosgird-core/src/secure_mem.rs). |
| [`tools/ct-check`](tools/ct-check) | The Valgrind constant-time check. | Not shipped. |
| [`tools/dudect`](tools/dudect), [`fuzz`](fuzz) | The timing test and the fuzz targets. | Not shipped; separate workspaces. |

## Verification

| Check | What it shows | Where it runs |
|---|---|---|
| Unit tests | Known answers (RFC 4648 vectors), errors, and edge cases. | Every pull request, on Linux x86-64 and arm64, macOS, and Windows. |
| Clippy (pedantic), rustfmt, rustdoc | Lints, including no `unwrap`, `expect`, `panic`, or printing in library code. | Every pull request. |
| [Miri](https://github.com/rust-lang/miri) | No undefined behavior in any test, including the `unsafe` in `secure_mem`, with strict provenance. | Every pull request. |
| `scripts/check_unsafe.sh` | `unsafe` appears in `secure_mem` and nowhere else. | Every pull request. |
| Constant time, Valgrind (`tools/ct-check`) | No branch and no memory address depends on secret input in the compiled release code. A negative control must be caught, or the check fails. | Every pull request. |
| [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) | No dependency with a RustSec advisory (the database cargo-audit uses), a disallowed license, or a source other than crates.io. | Every pull request. |
| [Actions lockfile](https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles) (`actions-lock.yml`) | Every action the workflows run, including the actions those actions use, is locked to a commit and to its repository's identity in `.github/workflows/actions.lock`, and the lock still verifies upstream. Dependabot proposes updates after a 7-day cooldown. | Every pull request. |
| Hardening (`scripts/check_hardening.sh`) | The release binary has the protections listed below. | Every pull request. |
| [Kani](https://github.com/model-checking/kani) | For every input up to the stated bounds: no panic, no overflow, no out-of-bounds access, and the stated property (round trips, canonical decoding, layouts that cover a request). | Pull requests that change Rust code, and weekly. |
| [hax](https://github.com/pereq-dev/hax) to F* | `mosgird-protocol` is in the subset hax extracts, and F* proves the extraction free of panics for inputs of any length: no out-of-bounds access, no overflow. The job fails if the extraction admits or assumes a proof obligation. | Pull requests that change Rust code, and weekly. |
| Fuzzing (cargo-fuzz) | No panic, and the decoder accepts only text that re-encodes to itself, for long and random inputs. | Weekly, 30 minutes per target. |
| dudect (`tools/dudect`) | No measurable timing difference between classes of secret input. | Weekly. |

**Not yet proved, and next:**

- **Functional correctness in F*.** F* proves panic freedom only. That decoding inverts encoding, and that only canonical text is accepted, is proved by Kani up to its bounds and fuzzed beyond them, not yet in F*.
- **Kani covers bounded inputs only:** up to 11 bytes and 18 characters for base32. Longer inputs repeat the same code paths, and are fuzzed.

Results of the local run that preceded the first pull request are in its description.

## Secrets

- **Types.** Secret bytes are held in `mosgird_crypto::Secret<N>` or, when they must not move, in `mosgird_core::secure_mem::LockedBox<N>`. Neither has `Clone`, `Copy`, `Debug`, `Display`, or `PartialEq`, so a secret cannot be copied, logged, or compared with `==` by mistake. The doctests of `Secret` check that such code does not compile. Comparison is through `subtle::ConstantTimeEq`.
- **Zeroing.** Both types are zeroed when dropped, with `zeroize`, whose volatile writes and barrier the compiler keeps. Buffers inside functions that held secret bytes are wiped before return.
- **Locked memory.** `LockedBox` memory is whole pages, locked into RAM (`mlock`, `VirtualLock`), left out of core dumps on Linux, Android, and FreeBSD (`MADV_DONTDUMP`, `MADV_NOCORE`), and it never moves.
- **Constant time.** Code that touches secrets has no branch, no table lookup, and no memory address that depends on them. Values are compared with masks, and the masks pass through an optimization barrier. The barrier is needed: without it, LLVM compiled the base32 range checks back into a conditional move, and the Valgrind check caught it.

**Open:**

- guard pages around `LockedBox`, and `mprotect` between uses;
- per-range dump exclusion on macOS, iOS, and Windows, where apps instead turn off core dumps or crash reports for the whole process;
- moving a `Secret` can leave a copy of its bytes on the stack. Code that must not leave copies uses `LockedBox`.

## Hardening

Release builds are optimized and hardened together:

- **Release profile.** `opt-level = 3`, fat LTO, one codegen unit, `panic = "abort"`, symbols stripped. Overflow checks stay on: an overflow aborts instead of wrapping silently.
- **Linux and Android.** Set in [`.cargo/config.toml`](.cargo/config.toml):
  - position-independent executables;
  - full RELRO with immediate binding;
  - a non-executable stack;
  - stack canaries (`-Z stack-protector=strong`);
  - on x86-64, Intel CET (`-Z cf-protection=full`);
- **Windows.** Control Flow Guard, ASLR with high entropy, DEP, and CET compatibility.
- **`cargo build-hardened --target <triple>`** rebuilds the standard library with the same flags, so the stack canaries also cover `std`. On arm64 Linux and Android it also adds pointer authentication and branch target identification (`-Z branch-protection=pac-ret,bti`). They change the ABI, so they cannot be mixed with the prebuilt `std`. Release builds of the apps use this alias, and the CI hardening job uses it.

**Open:**

- **The CET marker.** The linker marks a binary as CET-enabled only when every object, including the C runtime, carries the marker. On the development machine it does not yet, so `check_hardening.sh` reports CET but does not require it.
- **Android.** Shadow call stack and CFI sanitizers need `-Z build-std` for that target. They are set up and checked in the Android build.
- **Every target's flags** are checked by building on that target in CI. Only the Linux x86-64 binary is inspected so far.

## Building

The toolchain is a pinned nightly ([`rust-toolchain.toml`](rust-toolchain.toml)). rustup installs it on the first `cargo` command. Kani and hax install their own pinned nightlies.

```sh
cargo test --workspace --exclude ct-check
cargo clippy --workspace --all-targets -- -D warnings
cargo miri test --workspace --exclude ct-check
sh scripts/check_unsafe.sh

# Constant time. Needs Valgrind. On a distribution with a stripped ld.so,
# add RUSTFLAGS="-C target-feature=+crt-static" for a static build.
cargo build --profile ct -p ct-check
sh scripts/ct_check.sh target/ct/ct-check

cargo kani --workspace --exclude ct-check     # needs Kani 0.68.0
cargo deny check all
(cd fuzz && cargo fuzz run base32_decode -- -max_total_time=60)
sh scripts/dudect_check.sh
```

On a machine with little memory, cap the provers. For example, on Linux with systemd:

```sh
systemd-run --user --scope -p MemoryMax=3G -p MemorySwapMax=0 cargo kani --workspace --exclude ct-check
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Rules for AI tools and agents are in the protocol repository.
