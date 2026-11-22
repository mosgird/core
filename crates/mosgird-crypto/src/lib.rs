//! Types for secret material, and later the wrappers around the
//! cryptographic primitives of decision 0011.
//!
//! No primitive is wrapped yet. Decision 0013 has the core use verified
//! implementations (libcrux, from HACL* and hax) first, with libsodium
//! as the fallback, and the protocol models are still drafts awaiting
//! review. Until they are reviewed, this crate holds only the secret
//! types that every later wrapper returns.
//!
//! A [`Secret`]:
//! - is zeroed when it is dropped;
//! - has no `Clone`, `Copy`, `Debug`, `Display`, `PartialEq` or `Hash`,
//!   so it cannot be duplicated, logged, or compared with `==` by
//!   mistake;
//! - is compared only in constant time, with [`subtle::ConstantTimeEq`].
//!
//! Moving a value in Rust may leave a copy of its old bytes on the
//! stack. Code that must not leave copies keeps secrets in
//! `mosgird_core::secure_mem::LockedBox`, which never moves its bytes.

#![no_std]
#![forbid(unsafe_code)]

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// `N` bytes of secret material.
///
/// ```
/// use mosgird_crypto::Secret;
/// use subtle::ConstantTimeEq;
///
/// let a = Secret::from_bytes([7u8; 32]);
/// let b = Secret::from_bytes([7u8; 32]);
/// assert!(bool::from(a.ct_eq(&b)));
/// ```
///
/// Comparing with `==` does not compile:
///
/// ```compile_fail
/// use mosgird_crypto::Secret;
/// let a = Secret::from_bytes([7u8; 32]);
/// let b = Secret::from_bytes([7u8; 32]);
/// let _ = a == b;
/// ```
///
/// Neither does printing it:
///
/// ```compile_fail
/// use mosgird_crypto::Secret;
/// let a = Secret::from_bytes([7u8; 32]);
/// let _ = format!("{a:?}");
/// ```
///
/// Nor copying it:
///
/// ```compile_fail
/// use mosgird_crypto::Secret;
/// let a = Secret::from_bytes([7u8; 32]);
/// let _b = a.clone();
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Secret<N> {
    /// Takes ownership of `bytes`. The caller's array is moved in; if
    /// the caller keeps another copy, the caller must zero it.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Fills a new secret by calling `fill` on a zeroed buffer, so that
    /// the bytes are written only once, in place.
    pub fn new_with(fill: impl FnOnce(&mut [u8; N])) -> Self {
        let mut s = Self { bytes: [0u8; N] };
        fill(&mut s.bytes);
        s
    }

    /// Exposes the bytes for the duration of a borrow. The name makes
    /// each use of secret material easy to find in review.
    #[must_use]
    pub const fn expose(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> ConstantTimeEq for Secret<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_equality() {
        let a = Secret::from_bytes([1u8; 32]);
        let b = Secret::new_with(|buf| buf.fill(1));
        let c = Secret::new_with(|buf| {
            buf.fill(1);
            buf[31] = 2;
        });
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    #[test]
    fn zeroize_clears() {
        let mut a = Secret::from_bytes([9u8; 16]);
        a.zeroize();
        assert_eq!(a.expose(), &[0u8; 16]);
    }
}
