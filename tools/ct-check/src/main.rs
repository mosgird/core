//! Constant-time check under Valgrind, in the style of ctgrind.
//!
//! Secret inputs are marked as undefined memory. Valgrind's Memcheck then
//! reports every conditional branch and every memory address that depends
//! on them. Run:
//!
//! ```sh
//! cargo build --release -p ct-check
//! valgrind --error-exitcode=1 target/release/ct-check
//! valgrind --error-exitcode=1 target/release/ct-check --negative-control  # must fail
//! ```
//!
//! The first run must report no errors. The second runs a function that
//! branches on a secret on purpose, and must report one, which shows the
//! check is not vacuous. Results derived from secrets are never printed,
//! because printing would itself branch on them.

use std::ffi::c_void;
use std::hint::black_box;

use crabgrind::memcheck::{MemState, mark_memory};
use mosgird_crypto::Secret;
use mosgird_protocol::base32::{Case, decode_ct, encode};
use subtle::ConstantTimeEq;

/// Marks `buf` as secret: Memcheck treats its contents as undefined.
fn secret(buf: &[u8]) {
    // Outside Valgrind this request does nothing, and the check is void.
    if mark_memory(
        buf.as_ptr().cast::<c_void>(),
        buf.len(),
        MemState::Undefined,
    )
    .is_err()
    {
        eprintln!("ct-check: not running under Valgrind; run it with valgrind");
        std::process::exit(2);
    }
}

/// Marks `buf` as public again, after the part under test.
fn public(buf: &[u8]) {
    let _ = mark_memory(buf.as_ptr().cast::<c_void>(), buf.len(), MemState::Defined);
}

fn check_base32() {
    for case in [Case::Lower, Case::Upper] {
        // An invite secret's size, and every tail length around it.
        for len in 28..=37 {
            let data = [0x5au8; 37];
            let input = &data[..len];
            secret(input);
            let mut text = [0u8; 64];
            let n = encode(black_box(input), &mut text, case);
            public(input);

            let n = n.unwrap_or(0);
            secret(&text[..n]);
            let mut back = [0u8; 40];
            let r = decode_ct(black_box(&text[..n]), &mut back, case);
            // The validity mask is secret too; it is not branched on here.
            public(&text[..n]);
            black_box((&back, r.is_ok()));
        }
        // Invalid characters must be handled in constant time as well.
        let bad = *b"abc!efgh01234567";
        secret(&bad);
        let mut back = [0u8; 10];
        black_box(decode_ct(black_box(&bad), &mut back, case).is_ok());
        public(&bad);
    }
}

fn check_secret_eq() {
    let a = Secret::from_bytes([3u8; 32]);
    let b = Secret::new_with(|buf| {
        buf.fill(3);
        buf[17] = 4;
    });
    secret(a.expose());
    secret(b.expose());
    let eq = a.ct_eq(&b);
    // Turning the Choice into a bool is the declassification point: the
    // caller decides to reveal the result. Mark it public before that.
    let byte = eq.unwrap_u8();
    public(core::slice::from_ref(&byte));
    black_box(byte);
    public(a.expose());
    public(b.expose());
}

/// Branches on a secret on purpose. Valgrind must report it.
fn negative_control() {
    let data = [1u8; 8];
    secret(&data);
    // An early exit that depends on the secret: the compiler cannot turn
    // it into straight-line code, as it can a counting loop.
    let first = black_box(&data).iter().position(|&b| b == 1);
    // A table load at a secret index, which Memcheck reports as well.
    static TABLE: [u8; 256] = [0; 256];
    let looked_up = TABLE[usize::from(black_box(data[3]))];
    public(&data);
    black_box((first, looked_up));
}

fn main() {
    if std::env::args().any(|a| a == "--negative-control") {
        negative_control();
        return;
    }
    check_base32();
    check_secret_eq();
}
