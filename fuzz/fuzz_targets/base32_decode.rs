//! Arbitrary text: the decoder never panics, and whatever it accepts
//! encodes back to exactly the same text (it accepts only canonical
//! input). The Kani proofs cover this for short inputs; fuzzing covers
//! long ones.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mosgird_protocol::base32::{Case, decode, decode_ct, decoded_len, encode};

fuzz_target!(|data: &[u8]| {
    let Some((&first, text)) = data.split_first() else {
        return;
    };
    let case = if first & 1 == 0 { Case::Lower } else { Case::Upper };
    let mut out = vec![0u8; decoded_len(text.len()).unwrap_or(0)];
    let plain = decode(text, &mut out, case);
    let masked = decode_ct(text, &mut out.clone(), case);
    // Both forms agree on validity.
    assert_eq!(plain.is_ok(), matches!(masked, Ok((_, 0xff))));
    if let Ok(n) = plain {
        let mut again = vec![0u8; text.len()];
        assert_eq!(encode(&out[..n], &mut again, case), Ok(text.len()));
        assert_eq!(again, text);
    }
});
