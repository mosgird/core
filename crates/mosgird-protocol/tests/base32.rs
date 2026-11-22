// covers: crates/mosgird-protocol/src/base32.rs
//! Behavior of the public base32 API: the RFC 4648 vectors, the length
//! functions, the buffer contracts, the canonical-form rules, and
//! `decode_ct`'s validity mask.

// Overflow in a test is a failed test (overflow checks are on), and the
// casts below keep small loop counters that fit in a byte.
#![allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]

use mosgird_protocol::base32::{Case, Error, decode, decode_ct, decoded_len, encode, encoded_len};

/// RFC 4648, section 10, without padding.
const VECTORS: [(&[u8], &str); 7] = [
    (b"", ""),
    (b"f", "MY"),
    (b"fo", "MZXQ"),
    (b"foo", "MZXW6"),
    (b"foob", "MZXW6YQ"),
    (b"fooba", "MZXW6YTB"),
    (b"foobar", "MZXW6YTBOI"),
];

const CASES: [Case; 2] = [Case::Lower, Case::Upper];

/// Deterministic test bytes: a linear congruential sequence.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    let mut x = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x = x.wrapping_mul(97).wrapping_add(41);
        out.push(x);
    }
    out
}

/// Encodes into a fresh vector of exactly the needed size.
fn encode_vec(input: &[u8], case: Case) -> Vec<u8> {
    let mut out = vec![0u8; encoded_len(input.len()).unwrap_or(0)];
    let n = encode(input, &mut out, case).unwrap_or(usize::MAX);
    assert_eq!(n, out.len());
    out
}

/// Decodes into a fresh vector, or returns the error.
fn decode_vec(text: &[u8], case: Case) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; decoded_len(text.len()).unwrap_or(0)];
    let n = decode(text, &mut out, case)?;
    assert_eq!(n, out.len());
    Ok(out)
}

#[test]
fn vectors_through_decode_ct() {
    for (plain, text) in VECTORS {
        let mut out = [0u8; 8];
        let (n, ok) = decode_ct(text.as_bytes(), &mut out, Case::Upper).unwrap();
        assert_eq!(ok, 0xff, "{text}");
        assert_eq!(&out[..n], plain);
    }
}

#[test]
fn vectors_in_lower_case() {
    for (plain, text) in VECTORS {
        let lower = text.to_ascii_lowercase();
        assert_eq!(encode_vec(plain, Case::Lower), lower.as_bytes());
        assert_eq!(decode_vec(lower.as_bytes(), Case::Lower).unwrap(), plain);
    }
}

#[test]
fn the_cases_differ_only_in_letters() {
    for len in 0..=40 {
        let data = pattern(len, 3);
        let upper = encode_vec(&data, Case::Upper);
        let lower = encode_vec(&data, Case::Lower);
        assert_eq!(upper.to_ascii_lowercase(), lower, "length {len}");
    }
}

#[test]
fn all_zero_bytes_encode_to_the_first_letter() {
    assert_eq!(encode_vec(&[0u8; 5], Case::Upper), b"AAAAAAAA");
    assert_eq!(encode_vec(&[0u8; 5], Case::Lower), b"aaaaaaaa");
}

#[test]
fn all_one_bytes_encode_to_the_last_digit() {
    assert_eq!(encode_vec(&[0xffu8; 5], Case::Upper), b"77777777");
    assert_eq!(encode_vec(&[0xffu8; 5], Case::Lower), b"77777777");
}

#[test]
fn digit_only_text_decodes_in_both_cases() {
    for case in CASES {
        assert_eq!(decode_vec(b"77777777", case).unwrap(), [0xffu8; 5]);
    }
}

#[test]
fn every_single_byte_round_trips() {
    for case in CASES {
        for b in 0u8..=255 {
            let text = encode_vec(&[b], case);
            assert_eq!(text.len(), 2);
            assert_eq!(decode_vec(&text, case).unwrap(), [b]);
        }
    }
}

#[test]
fn every_length_round_trips_in_both_cases() {
    for case in CASES {
        for len in 0..=80 {
            let data = pattern(len, len as u8);
            let text = encode_vec(&data, case);
            assert_eq!(decode_vec(&text, case).unwrap(), data, "length {len}");
        }
    }
}

#[test]
fn onion_and_i2p_lengths() {
    // An onion v3 address is 35 bytes, 56 characters; an I2P
    // destination hash is 32 bytes, 52 characters.
    assert_eq!(encoded_len(35), Some(56));
    assert_eq!(decoded_len(56), Some(35));
    assert_eq!(encoded_len(32), Some(52));
    assert_eq!(decoded_len(52), Some(32));
    let onion = pattern(35, 9);
    assert_eq!(encode_vec(&onion, Case::Lower).len(), 56);
}

#[test]
fn encoded_len_by_tail() {
    let expected = [0, 2, 4, 5, 7, 8, 10, 12, 13, 15, 16];
    for (len, chars) in expected.into_iter().enumerate() {
        assert_eq!(encoded_len(len), Some(chars), "length {len}");
    }
}

#[test]
fn decoded_len_by_tail() {
    let expected = [
        Some(0),
        None,
        Some(1),
        None,
        Some(2),
        Some(3),
        None,
        Some(4),
        Some(5),
        None,
    ];
    for (len, bytes) in expected.into_iter().enumerate() {
        assert_eq!(decoded_len(len), bytes, "length {len}");
    }
}

#[test]
fn encoded_len_at_the_limit() {
    // The largest input whose length in characters fits a usize.
    let largest = usize::MAX / 8 * 5;
    assert!(encoded_len(largest).is_some());
    assert_eq!(encoded_len(largest + 5), None);
    assert_eq!(encoded_len(usize::MAX), None);
}

#[test]
fn decoded_len_never_overflows() {
    for len in [usize::MAX, usize::MAX - 1, usize::MAX - 3, usize::MAX - 7] {
        if let Some(bytes) = decoded_len(len) {
            assert!(bytes <= len);
        }
    }
    assert_eq!(decoded_len(usize::MAX - 7), Some((usize::MAX - 7) / 8 * 5));
}

#[test]
fn lengths_are_inverse() {
    for len in 0..1000 {
        let chars = encoded_len(len).unwrap();
        assert_eq!(decoded_len(chars), Some(len));
    }
}

#[test]
fn empty_input() {
    let mut out = [0u8; 0];
    for case in CASES {
        assert_eq!(encode(&[], &mut out, case), Ok(0));
        assert_eq!(decode(&[], &mut out, case), Ok(0));
        assert_eq!(decode_ct(&[], &mut out, case), Ok((0, 0xff)));
    }
}

#[test]
fn encode_into_an_exact_buffer() {
    for len in 0..=20 {
        let data = pattern(len, 1);
        let mut out = vec![0u8; encoded_len(len).unwrap()];
        assert_eq!(encode(&data, &mut out, Case::Upper), Ok(out.len()));
    }
}

#[test]
fn encode_into_a_buffer_one_short_fails() {
    for len in 1..=20 {
        let data = pattern(len, 1);
        let mut out = vec![0u8; encoded_len(len).unwrap() - 1];
        assert_eq!(
            encode(&data, &mut out, Case::Upper),
            Err(Error::OutputTooSmall),
            "length {len}"
        );
    }
}

#[test]
fn failed_encode_writes_nothing() {
    let mut out = [0x5au8; 7];
    assert_eq!(
        encode(b"foobar", &mut out, Case::Upper),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(out, [0x5au8; 7]);
}

#[test]
fn encode_leaves_the_rest_of_the_buffer_alone() {
    let mut out = [0x5au8; 16];
    let n = encode(b"foo", &mut out, Case::Upper).unwrap();
    assert_eq!(&out[..n], b"MZXW6");
    assert!(out[n..].iter().all(|&b| b == 0x5a));
}

#[test]
fn decode_leaves_the_rest_of_the_buffer_alone() {
    let mut out = [0x5au8; 16];
    let n = decode(b"MZXW6", &mut out, Case::Upper).unwrap();
    assert_eq!(&out[..n], b"foo");
    assert!(out[n..].iter().all(|&b| b == 0x5a));
}

#[test]
fn decode_into_an_exact_buffer() {
    for (plain, text) in VECTORS {
        let mut out = vec![0u8; plain.len()];
        assert_eq!(
            decode(text.as_bytes(), &mut out, Case::Upper),
            Ok(plain.len())
        );
        assert_eq!(out, plain);
    }
}

#[test]
fn decode_into_a_buffer_one_short_fails() {
    for (plain, text) in VECTORS.into_iter().skip(1) {
        let mut out = vec![0u8; plain.len() - 1];
        assert_eq!(
            decode(text.as_bytes(), &mut out, Case::Upper),
            Err(Error::OutputTooSmall),
            "{text}"
        );
        assert_eq!(
            decode_ct(text.as_bytes(), &mut out, Case::Upper),
            Err(Error::OutputTooSmall),
            "{text}"
        );
    }
}

#[test]
fn invalid_lengths_are_rejected_before_the_buffer_size() {
    let mut out = [0u8; 0];
    for len in [1, 3, 6, 9, 11, 14, 17] {
        let text = vec![b'A'; len];
        assert_eq!(
            decode(&text, &mut out, Case::Upper),
            Err(Error::InvalidLength),
            "length {len}"
        );
        assert_eq!(
            decode_ct(&text, &mut out, Case::Upper),
            Err(Error::InvalidLength),
            "length {len}"
        );
    }
}

#[test]
fn every_invalid_character_in_every_position_is_rejected() {
    let valid = *b"MZXW6YTB";
    let invalid = [
        b'=', b'0', b'1', b'8', b'9', b' ', b'm', b'@', b'[', 0, 0xff,
    ];
    for pos in 0..valid.len() {
        for bad in invalid {
            let mut text = valid;
            text[pos] = bad;
            assert_eq!(
                decode_vec(&text, Case::Upper),
                Err(Error::InvalidEncoding),
                "byte {bad} at {pos}"
            );
        }
    }
}

#[test]
fn upper_case_letters_are_invalid_in_lower_case() {
    assert_eq!(
        decode_vec(b"MZXW6YTB", Case::Lower),
        Err(Error::InvalidEncoding)
    );
    assert_eq!(
        decode_vec(b"mzxW6ytb", Case::Lower),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn lower_case_letters_are_invalid_in_upper_case() {
    assert_eq!(
        decode_vec(b"mzxw6ytb", Case::Upper),
        Err(Error::InvalidEncoding)
    );
    assert_eq!(
        decode_vec(b"MZXw6YTB", Case::Upper),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn set_unused_bits_are_rejected_for_every_tail() {
    // Tails of 2, 4, 5 and 7 characters leave 2, 4, 1 and 3 unused bits.
    // The canonical last character has them clear, so the next character
    // in the alphabet sets the lowest unused bit.
    for case in CASES {
        for len in 1..=24 {
            if len % 5 == 0 {
                continue;
            }
            let data = pattern(len, 77);
            let mut text = encode_vec(&data, case);
            let last = text.len() - 1;
            text[last] = next_in_alphabet(text[last], case);
            assert_eq!(
                decode_vec(&text, case),
                Err(Error::InvalidEncoding),
                "length {len}"
            );
        }
    }
}

/// The character after `c` in the alphabet of `case` (wrapping).
fn next_in_alphabet(c: u8, case: Case) -> u8 {
    let (z, a) = match case {
        Case::Lower => (b'z', b'a'),
        Case::Upper => (b'Z', b'A'),
    };
    match c {
        _ if c == z => b'2',
        b'7' => a,
        _ => c.wrapping_add(1),
    }
}

#[test]
fn full_blocks_have_no_unused_bits() {
    // Every character of a full block carries data, so changing the last
    // one changes the bytes instead of being rejected.
    let text = encode_vec(b"fooba", Case::Upper);
    let mut changed = text.clone();
    changed[7] = next_in_alphabet(changed[7], Case::Upper);
    let bytes = decode_vec(&changed, Case::Upper).unwrap();
    assert_ne!(bytes, b"fooba");
    assert_eq!(&bytes[..4], b"foob");
}

#[test]
fn rejected_input_zeroes_the_decoded_part() {
    let mut out = [0xaau8; 12];
    assert_eq!(
        decode(b"MZXW6YTBOI=", &mut out, Case::Upper),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        decode(b"MZXW6YTBO!", &mut out, Case::Upper),
        Err(Error::InvalidEncoding)
    );
    assert_eq!(out[..6], [0u8; 6]);
    assert_eq!(out[6..], [0xaau8; 6]);
}

#[test]
fn decode_ct_marks_invalid_input_and_zeroes_it() {
    let mut out = [0xaau8; 8];
    let (n, ok) = decode_ct(b"MZXW6YT!", &mut out, Case::Upper).unwrap();
    assert_eq!((n, ok), (5, 0));
    assert_eq!(out[..5], [0u8; 5]);
    assert_eq!(out[5..], [0xaau8; 3]);
}

#[test]
fn decode_ct_marks_non_canonical_input() {
    let mut out = [0u8; 1];
    assert_eq!(decode_ct(b"MZ", &mut out, Case::Upper), Ok((1, 0)));
    assert_eq!(out, [0]);
    assert_eq!(decode_ct(b"MY", &mut out, Case::Upper), Ok((1, 0xff)));
    assert_eq!(out, *b"f");
}

#[test]
fn decode_ct_mask_is_all_or_nothing() {
    for len in 0..=30 {
        let data = pattern(len, 5);
        let text = encode_vec(&data, Case::Lower);
        let mut out = vec![0u8; len];
        let (n, ok) = decode_ct(&text, &mut out, Case::Lower).unwrap();
        assert_eq!((n, ok), (len, 0xff));
        assert_eq!(out, data);
        let (n, ok) = decode_ct(&text, &mut out, Case::Upper).unwrap();
        // Text with only digits is valid in both cases.
        let digits_only = text.iter().all(u8::is_ascii_digit);
        assert_eq!(n, len);
        assert_eq!(ok, if digits_only { 0xff } else { 0 }, "length {len}");
    }
}

#[test]
fn decode_and_decode_ct_agree() {
    let texts: [&[u8]; 8] = [
        b"",
        b"MY",
        b"MZ",
        b"my",
        b"MZXW6YTB",
        b"MZXW6YT!",
        b"77777777",
        b"AAAAAAAA",
    ];
    for text in texts {
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        let plain = decode(text, &mut a, Case::Upper);
        let (n, ok) = decode_ct(text, &mut b, Case::Upper).unwrap();
        match plain {
            Ok(m) => {
                assert_eq!((m, ok), (n, 0xff));
                assert_eq!(a[..m], b[..n]);
            }
            Err(e) => {
                assert_eq!((e, ok), (Error::InvalidEncoding, 0));
                assert!(b[..n].iter().all(|&x| x == 0));
            }
        }
    }
}

#[test]
fn decoding_a_long_input() {
    let data = pattern(1000, 11);
    let text = encode_vec(&data, Case::Upper);
    assert_eq!(text.len(), 1600);
    assert_eq!(decode_vec(&text, Case::Upper).unwrap(), data);
}

#[test]
fn case_and_error_are_plain_values() {
    let case = Case::Lower;
    let copy = case;
    assert_eq!(case, copy);
    assert_ne!(Case::Lower, Case::Upper);
    assert_eq!(format!("{:?}", Case::Upper), "Upper");
    let err = Error::InvalidLength;
    let again = err;
    assert_eq!(err, again);
    assert_eq!(format!("{:?}", Error::OutputTooSmall), "OutputTooSmall");
    assert_eq!(format!("{:?}", Error::InvalidEncoding), "InvalidEncoding");
    assert_ne!(Error::InvalidLength, Error::InvalidEncoding);
}
