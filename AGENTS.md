# Agent rules

The rules for AI agents and contributors are kept once, in the protocol repository:

- [AGENTS.md](https://github.com/mosgird/protocols/blob/main/AGENTS.md)
- [AI_POLICY.md](https://github.com/mosgird/protocols/blob/main/AI_POLICY.md)
- [CONTRIBUTING.md](https://github.com/mosgird/protocols/blob/main/CONTRIBUTING.md)

Read them before making changes. This file only points to them.

## Protocol details

The protocol is specified in [mosgird/protocols](https://github.com/mosgird/protocols). Before implementing, changing, or documenting protocol behavior, read the specification there, starting with `spec/v0.1/overview.md` and the decision records in `spec/decisions/`. Wire formats, cryptographic procedures, and test vectors are defined there, not in this repository. If this repository and the specification disagree, the specification is correct. Propose a specification change in the protocol repository before changing behavior here.

## Test-driven development

Work test first: write a failing test, then the least code that passes it, then refactor. Keep at least 3 lines of test code per line of production code, counted without blank lines and comments, for this repository, for each unit (crate), and for each production file. Fuzz targets, Kani harnesses, hax annotations and test tools count as tests. Whole test files name what they test in a `covers:` comment.

The full rule is in the protocol repository's [AGENTS.md](https://github.com/mosgird/protocols/blob/main/AGENTS.md#test-driven-development). The required `test-ratio` check enforces it. To run it locally, with the protocol repository checked out beside this one:

```sh
python3 ../protocols/scripts/check_test_ratio.py .
```

## Rules specific to the core

These apply to people and to AI tools alike.

- **`unsafe` lives in one module:** `crates/mosgird-core/src/secure_mem.rs`. Every `unsafe` block there has a `// SAFETY:` comment saying why it is sound. Do not add `unsafe` anywhere else, and do not relax the `unsafe_code` lint. `scripts/check_unsafe.sh` enforces this. A new need for `unsafe` (for example, FFI to libsodium) goes into that module, or into a new one that a pull request of its own creates and justifies.
- **Secrets** are held in `mosgird_crypto::Secret` or `mosgird_core::secure_mem::LockedBox`.
  - Never derive or implement `Clone`, `Copy`, `Debug`, `Display`, `PartialEq`, or `Hash` on a type that holds secret material.
  - Compare secrets only with `subtle::ConstantTimeEq`.
  - Never log or print them, including in errors.
- **Constant time.**
  - Code that handles secrets has no branch, no table lookup, and no memory index that depends on them.
  - New such code gets a case in `tools/ct-check`, and that check must pass.
  - Mask arithmetic passes through an optimization barrier, as in `base32.rs`; the compiler can otherwise turn it back into branches.
- **Panics.** Library code does not panic: no `unwrap`, `expect`, `panic!`, or unchecked indexing that a proof does not cover. Errors are returned.
- **`mosgird-protocol` stays in the hax subset:** no `unsafe`, no allocation, no I/O, no trait objects, plain loops. The `verify` workflow extracts it.
- **Proofs move with the code.** A change to a function with a Kani harness updates the harness in the same pull request. Do not weaken a harness's bound or property to make it pass; record the problem as an issue instead.
- **No cryptographic primitive is implemented here.** Primitives come from libcrux, with libsodium as the fallback (decision 0013). A wire format is implemented only after the specification defines it.
- **Do not change the toolchain date, the hardening flags, or the release profile** except in a pull request of its own that says why.
