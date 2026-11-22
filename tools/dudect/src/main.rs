// covers: crates/mosgird-protocol/src/base32.rs
//! Statistical timing test (dudect: Reparaz, Balasch, Verbauwhede, 2016).
//!
//! The Valgrind check in `tools/ct-check` finds branches and addresses
//! that depend on secrets. This test measures time instead, so it can
//! catch what Valgrind cannot see, such as a variable-time instruction.
//! It needs many samples and a quiet machine, so it runs weekly in CI
//! (`.github/workflows/fuzz.yml`), not on every pull request.
//!
//! Run: `cargo run --release -p dudect`. Each test prints a t statistic.
//! As dudect's authors suggest, |t| above 5 means a timing difference
//! is likely; `scripts/dudect_check.sh` fails above 10 to leave room for
//! noise on shared CI runners.

use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};
use mosgird_protocol::base32::{Case, decode_ct, encode};

const SAMPLES: usize = 200_000;
const SECRET_LEN: usize = 32;
const TEXT_LEN: usize = 52;

/// A small deterministic generator (SplitMix64), so that the inputs do
/// not depend on the version of `rand` that dudect-bencher uses.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.next() as u8;
        }
    }
}

/// Encoding all-zero secrets (Left) against random secrets (Right).
fn base32_encode(runner: &mut CtRunner, _: &mut BenchRng) {
    let mut prng = SplitMix(1);
    let mut inputs = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let mut secret = [0u8; SECRET_LEN];
        let class = if prng.next() & 1 == 0 {
            Class::Left
        } else {
            prng.fill(&mut secret);
            Class::Right
        };
        inputs.push((class, secret));
    }
    for (class, secret) in inputs {
        runner.run_one(class, || {
            let mut out = [0u8; TEXT_LEN];
            encode(&secret, &mut out, Case::Lower).map(|_| out)
        });
    }
}

/// Decoding valid text of random secrets (Left) against text with one
/// invalid character at a random place (Right). A decoder that stops at
/// the first bad character would show here.
fn base32_decode(runner: &mut CtRunner, _: &mut BenchRng) {
    let mut prng = SplitMix(2);
    let mut inputs = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let mut secret = [0u8; SECRET_LEN];
        prng.fill(&mut secret);
        let mut text = [0u8; TEXT_LEN];
        let _ = encode(&secret, &mut text, Case::Lower);
        let class = if prng.next() & 1 == 0 {
            Class::Left
        } else {
            let at = (prng.next() % TEXT_LEN as u64) as usize;
            text[at] = b'!';
            Class::Right
        };
        inputs.push((class, text));
    }
    for (class, text) in inputs {
        runner.run_one(class, || {
            let mut out = [0u8; SECRET_LEN];
            decode_ct(&text, &mut out, Case::Lower).map(|(_, ok)| (out, ok))
        });
    }
}

ctbench_main!(base32_encode, base32_decode);
