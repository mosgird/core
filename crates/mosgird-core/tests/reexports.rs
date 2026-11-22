// covers: crates/mosgird-core/src/lib.rs
//! The core crate's public paths: the protocol and crypto crates are
//! re-exported, and `secure_mem` is public.

use mosgird_core::crypto::Secret;
use mosgird_core::protocol::base32::{Case, decode, encode};
use mosgird_core::secure_mem::LockedBox;

/// Accepts only the crypto crate's own type, so the call below checks
/// that the re-export is that type and not a copy of it.
fn first_byte(s: &mosgird_crypto::Secret<8>) -> u8 {
    s.expose()[0]
}

#[test]
fn crypto_is_reexported() {
    let a = Secret::from_bytes([1u8; 8]);
    assert_eq!(first_byte(&a), 1);
}

#[test]
fn protocol_is_reexported() {
    let mut text = [0u8; 4];
    let n = encode(b"fo", &mut text, Case::Upper).unwrap();
    assert_eq!(&text[..n], b"MZXQ");
    let mut plain = [0u8; 2];
    assert_eq!(decode(&text, &mut plain, Case::Upper), Ok(2));
    assert_eq!(&plain, b"fo");
}

#[test]
fn secure_mem_is_public() {
    let b = LockedBox::<4>::new_with(|buf| buf.fill(2)).unwrap();
    assert_eq!(b.expose(), &[2u8; 4]);
}
