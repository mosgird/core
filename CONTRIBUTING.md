# Contributing to Mosgird core

The contribution process for this repository is the same as for the protocol repository. See [CONTRIBUTING.md](https://github.com/mosgird/protocols/blob/main/CONTRIBUTING.md).

This repository adds these requirements:

- The `contribution-policy` check and the `ci` checks must pass before a pull request can merge.
- A pull request that changes code under `crates/` runs the `verify` workflow (Kani and hax), and it must pass.
- A new dependency is explained in the pull request description, and must pass `cargo deny check all`.
- The rules for `unsafe` code and secrets in [AGENTS.md](AGENTS.md) apply to everyone, not only to AI tools.

Implementation details for the core belong in this repository, in its own documentation. Protocol behavior belongs in the protocol repository.
