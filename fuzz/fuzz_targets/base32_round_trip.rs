// covers: crates/mosgird-protocol/src/base32.rs
//! Arbitrary bytes: encoding and then decoding gives the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mosgird_protocol::base32::{Case, decode, encode, encoded_len};

fuzz_target!(|data: &[u8]| {
    for case in [Case::Lower, Case::Upper] {
        let Some(len) = encoded_len(data.len()) else {
            return;
        };
        let mut text = vec![0u8; len];
        assert_eq!(encode(data, &mut text, case), Ok(len));
        let mut back = vec![0u8; data.len()];
        assert_eq!(decode(&text, &mut back, case), Ok(data.len()));
        assert_eq!(back, data);
    }
});
