//! Mosgird protocol logic: wire formats and state machines, with no I/O
//! and no cryptographic primitives of its own.
//!
//! This crate is the part of the core that is extracted with hax and
//! checked in F*. It keeps to the subset of Rust that hax supports:
//! no `unsafe`, no allocation, no I/O, plain loops over indices. See
//! README.md, "Verification".
//!
//! The specification is in <https://github.com/mosgird/protocols>. Where
//! this crate and the specification disagree, the specification is
//! correct.
//!
//! Contents so far:
//! - [`base32`]: the RFC 4648 encoding of onion and I2P addresses and of
//!   the invite link (decisions 0009 and 0014).
//!
//! The layout of the invite link is not here yet. Decision 0014 leaves
//! the exact encoding to the specification text, and it is not written.

#![no_std]
#![forbid(unsafe_code)]

pub mod base32;
