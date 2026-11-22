// covers: crates/mosgird-protocol/src/lib.rs
//! The protocol crate's public paths, and that it builds without `std`
//! for its users: `base32` is reachable and works on plain arrays.

use mosgird_protocol::base32;

#[test]
fn base32_module_is_public() {
    let mut text = [0u8; 8];
    let n = base32::encode(b"fooba", &mut text, base32::Case::Lower).unwrap();
    assert_eq!(&text[..n], b"mzxw6ytb");
}

#[test]
fn base32_lengths_are_public() {
    assert_eq!(base32::encoded_len(5), Some(8));
    assert_eq!(base32::decoded_len(8), Some(5));
}
