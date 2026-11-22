// covers: crates/mosgird-crypto/src/lib.rs
//! Behavior of `Secret` through its public API: construction, exposure,
//! constant-time comparison, and zeroizing.

use mosgird_crypto::Secret;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

fn equal<const N: usize>(a: &Secret<N>, b: &Secret<N>) -> bool {
    bool::from(a.ct_eq(b))
}

#[test]
fn from_bytes_keeps_the_bytes() {
    let s = Secret::from_bytes([1, 2, 3, 4]);
    assert_eq!(s.expose(), &[1, 2, 3, 4]);
}

#[test]
fn from_bytes_is_usable_in_constants() {
    const S: Secret<2> = Secret::from_bytes([8, 9]);
    assert_eq!(S.expose(), &[8, 9]);
}

#[test]
fn new_with_starts_from_zero() {
    let mut seen_zero = false;
    let s = Secret::<16>::new_with(|buf| {
        seen_zero = buf.iter().all(|&x| x == 0);
        buf[3] = 7;
    });
    assert!(seen_zero);
    assert_eq!(s.expose()[3], 7);
    assert_eq!(s.expose().iter().filter(|&&x| x != 0).count(), 1);
}

#[test]
fn equality_is_reflexive() {
    let s = Secret::from_bytes([5u8; 32]);
    assert!(equal(&s, &s));
}

#[test]
fn a_difference_in_any_byte_is_seen() {
    let base = Secret::from_bytes([0x33u8; 32]);
    for i in 0..32 {
        let other = Secret::<32>::new_with(|buf| {
            buf.fill(0x33);
            buf[i] ^= 1;
        });
        assert!(!equal(&base, &other), "byte {i}");
        assert!(!equal(&other, &base), "byte {i}");
    }
}

#[test]
fn zero_sized_secrets_are_equal() {
    assert!(equal(&Secret::from_bytes([]), &Secret::from_bytes([])));
}

#[test]
fn zeroize_clears_every_byte() {
    let mut s = Secret::from_bytes([0xffu8; 64]);
    s.zeroize();
    assert_eq!(s.expose(), &[0u8; 64]);
    assert!(equal(&s, &Secret::from_bytes([0u8; 64])));
}
