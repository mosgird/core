//! The Mosgird core library: storage, transports, and the interface to
//! the apps, built on `mosgird-protocol` and `mosgird-crypto`.
//!
//! Contents so far:
//! - [`secure_mem`]: locked, non-moving memory for secrets. It is the
//!   only module in the workspace allowed to use `unsafe`.
//!
//! Storage (decision 0015), the transports (decision 0009), and the
//! interface to the apps come later, each in its own pull request.

#![deny(unsafe_code)]

pub use mosgird_crypto as crypto;
pub use mosgird_protocol as protocol;

// The one module with `unsafe`. Its unsafe blocks each state why they are
// sound, and it is checked by Miri and Kani in CI.
#[allow(unsafe_code)]
pub mod secure_mem;
