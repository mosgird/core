//! Base32 without padding, as in RFC 4648, section 6.
//!
//! Onion addresses and I2P destination hashes are written in this
//! encoding, and decision 0014 encodes the invite link with it. The
//! link carries the invite secret, so the encoder and the decoder are
//! constant-time: no branch and no memory access depends on the value
//! of a byte or a character. They depend only on lengths, which are
//! public.
//!
//! The decoder is strict. It accepts only the canonical encoding in the
//! requested case, so every byte string has exactly one accepted text
//! form:
//! - no padding characters (`=`), no whitespace, no other case;
//! - a length that RFC 4648 can produce (not 1, 3 or 6 modulo 8);
//! - unused bits in the last character set to zero.
//!
//! Checked by: unit tests and Miri; Kani proofs of panic freedom and
//! round trips (below); fuzzing (`fuzz/`); and a Valgrind check that no
//! branch depends on secret input (`tools/ct-check`).

// Panic freedom and the absence of overflow in this module are proved
// by the Kani harnesses at the end of the file, for all inputs up to
// the bounds stated there. Indexing is kept, because hax extracts plain
// index loops more directly than iterator adaptors. The casts to u8
// truncate on purpose: they keep the low bits of masked values. The
// helpers are always inlined so that no call depends on secret data.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::inline_always
)]

/// The two alphabets of RFC 4648 base32 that Mosgird uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Case {
    /// `a` to `z`, then `2` to `7`. Onion and I2P addresses use this.
    Lower,
    /// `A` to `Z`, then `2` to `7`. QR codes store it most compactly.
    Upper,
}

/// Why encoding or decoding failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The output buffer is shorter than [`encoded_len`] or
    /// [`decoded_len`] requires.
    OutputTooSmall,
    /// The input length is 1, 3 or 6 modulo 8, which no byte string
    /// encodes to.
    InvalidLength,
    /// A character is outside the alphabet, or the unused bits of the
    /// last character are not zero. The position is not reported, so
    /// that the error says nothing about secret input.
    InvalidEncoding,
}

/// Characters per full block of five bytes.
const BLOCK_CHARS: usize = 8;
/// Bytes per full block.
const BLOCK_BYTES: usize = 5;

/// The number of characters that `len` bytes encode to, or `None` if
/// it does not fit in a `usize`.
#[must_use]
pub const fn encoded_len(len: usize) -> Option<usize> {
    let tail = match len % BLOCK_BYTES {
        0 => 0,
        1 => 2,
        2 => 4,
        3 => 5,
        _ => 7,
    };
    match (len / BLOCK_BYTES).checked_mul(BLOCK_CHARS) {
        Some(full) => full.checked_add(tail),
        None => None,
    }
}

/// The number of bytes that `len` characters decode to, or `None` if
/// no byte string encodes to `len` characters.
#[must_use]
pub const fn decoded_len(len: usize) -> Option<usize> {
    let tail = match len % BLOCK_CHARS {
        0 => 0,
        2 => 1,
        4 => 2,
        5 => 3,
        7 => 4,
        _ => return None,
    };
    // len / 8 * 5 <= len, so this cannot overflow.
    Some(len / BLOCK_CHARS * BLOCK_BYTES + tail)
}

/// The number of characters a tail of `bytes` bytes needs (1 to 4).
const fn tail_chars(bytes: usize) -> usize {
    match bytes {
        1 => 2,
        2 => 4,
        3 => 5,
        _ => 7,
    }
}

/// The number of bytes a tail of `chars` characters holds.
const fn tail_bytes(chars: usize) -> usize {
    match chars {
        2 => 1,
        4 => 2,
        5 => 3,
        _ => 4,
    }
}

/// All ones if `a < b`, else zero. Both must be below 256.
#[inline(always)]
fn mask_lt(a: u16, b: u16) -> u8 {
    // a - b wraps to a value with the top bit set exactly when a < b.
    barrier((a.wrapping_sub(b) >> 15).wrapping_neg() as u8)
}

/// Hides a mask's value from the optimizer.
///
/// Without it, LLVM recognizes the range checks in `from_char` and
/// compiles them back into a conditional move on the character, which
/// the Valgrind check in `tools/ct-check` caught. `subtle` uses the same
/// barrier. hax reasons about values, not machine code, so it sees the
/// identity function.
#[inline(always)]
fn barrier(x: u8) -> u8 {
    #[cfg(not(hax))]
    {
        core::hint::black_box(x)
    }
    #[cfg(hax)]
    {
        x
    }
}

/// Maps a 5-bit value to its character, without a table or a branch.
#[inline(always)]
fn to_char(value: u8, case: Case) -> u8 {
    let v = u16::from(value & 0x1f);
    let letter_base = u16::from(match case {
        Case::Lower => b'a',
        Case::Upper => b'A',
    });
    let is_letter = mask_lt(v, 26);
    let letter = (v + letter_base) as u8;
    // '2' is 50, and v - 26 + 50 = v + 24.
    let digit = (v + 24) as u8;
    (letter & is_letter) | (digit & !is_letter)
}

/// Maps a character to its 5-bit value. Returns the value and a mask
/// that is all ones if the character is in the alphabet.
#[inline(always)]
fn from_char(c: u8, case: Case) -> (u8, u8) {
    let c16 = u16::from(c);
    let letter_base = u16::from(match case {
        Case::Lower => b'a',
        Case::Upper => b'A',
    });
    let is_letter = !mask_lt(c16, letter_base) & mask_lt(c16, letter_base + 26);
    let is_digit = !mask_lt(c16, u16::from(b'2')) & mask_lt(c16, u16::from(b'8'));
    let letter = c16.wrapping_sub(letter_base) as u8;
    let digit = c16.wrapping_sub(24) as u8;
    let value = (letter & is_letter) | (digit & is_digit);
    (value & 0x1f, is_letter | is_digit)
}

/// Writes the eight characters of one five-byte block.
#[inline(always)]
fn encode_block(b: &[u8; BLOCK_BYTES], out: &mut [u8; BLOCK_CHARS], case: Case) {
    out[0] = to_char(b[0] >> 3, case);
    out[1] = to_char((b[0] << 2) | (b[1] >> 6), case);
    out[2] = to_char(b[1] >> 1, case);
    out[3] = to_char((b[1] << 4) | (b[2] >> 4), case);
    out[4] = to_char((b[2] << 1) | (b[3] >> 7), case);
    out[5] = to_char(b[3] >> 2, case);
    out[6] = to_char((b[3] << 3) | (b[4] >> 5), case);
    out[7] = to_char(b[4], case);
}

/// Decodes one eight-character block. Returns all ones if every
/// character is in the alphabet.
#[inline(always)]
fn decode_block(c: &[u8; BLOCK_CHARS], out: &mut [u8; BLOCK_BYTES], case: Case) -> u8 {
    let mut v = [0u8; BLOCK_CHARS];
    let mut ok = 0xffu8;
    for i in 0..BLOCK_CHARS {
        let (value, valid) = from_char(c[i], case);
        v[i] = value;
        ok &= valid;
    }
    out[0] = (v[0] << 3) | (v[1] >> 2);
    out[1] = (v[1] << 6) | (v[2] << 1) | (v[3] >> 4);
    out[2] = (v[3] << 4) | (v[4] >> 1);
    out[3] = (v[4] << 7) | (v[5] << 2) | (v[6] >> 3);
    out[4] = (v[6] << 5) | v[7];
    ok
}

/// Encodes `input` into the start of `out`, and returns the number of
/// characters written, which is [`encoded_len`] of the input length.
///
/// # Errors
///
/// [`Error::OutputTooSmall`] if `out` is too short. Nothing is written
/// then.
pub fn encode(input: &[u8], out: &mut [u8], case: Case) -> Result<usize, Error> {
    let Some(needed) = encoded_len(input.len()) else {
        return Err(Error::OutputTooSmall);
    };
    if out.len() < needed {
        return Err(Error::OutputTooSmall);
    }
    let full = input.len() / BLOCK_BYTES;
    let mut bytes = [0u8; BLOCK_BYTES];
    let mut chars = [0u8; BLOCK_CHARS];
    for blk in 0..full {
        for j in 0..BLOCK_BYTES {
            bytes[j] = input[blk * BLOCK_BYTES + j];
        }
        encode_block(&bytes, &mut chars, case);
        for j in 0..BLOCK_CHARS {
            out[blk * BLOCK_CHARS + j] = chars[j];
        }
    }
    let rest = input.len() - full * BLOCK_BYTES;
    if rest > 0 {
        bytes = [0u8; BLOCK_BYTES];
        for j in 0..rest {
            bytes[j] = input[full * BLOCK_BYTES + j];
        }
        encode_block(&bytes, &mut chars, case);
        for j in 0..tail_chars(rest) {
            out[full * BLOCK_CHARS + j] = chars[j];
        }
    }
    // The block buffers held input bytes, which may be secret.
    wipe(&mut bytes);
    wipe(&mut chars);
    Ok(needed)
}

/// Decodes `input` into the start of `out`, and returns the number of
/// bytes written, which is [`decoded_len`] of the input length.
///
/// The time taken depends only on the input length. Whether the input
/// is valid is decided after every character has been read.
///
/// # Errors
///
/// - [`Error::InvalidLength`] if no byte string encodes to the input
///   length.
/// - [`Error::OutputTooSmall`] if `out` is too short.
/// - [`Error::InvalidEncoding`] if the input is not the canonical
///   encoding in `case`.
///
/// On error, the first [`decoded_len`] bytes of `out` (or all of it, if
/// shorter) are zero, so no part of a rejected secret is left behind.
pub fn decode(input: &[u8], out: &mut [u8], case: Case) -> Result<usize, Error> {
    let (n, valid) = decode_ct(input, out, case)?;
    if valid == 0xff {
        Ok(n)
    } else {
        Err(Error::InvalidEncoding)
    }
}

/// Like [`decode`], but without any branch on the input characters.
///
/// Returns the number of bytes and a mask that is `0xff` if the input
/// is the canonical encoding in `case` and `0x00` if not. If the mask
/// is `0x00`, the bytes written are all zero. Use this when even the
/// validity of the input must stay secret until a later, constant-time
/// step decides.
///
/// # Errors
///
/// [`Error::InvalidLength`] and [`Error::OutputTooSmall`], as for
/// [`decode`]. These depend only on lengths.
pub fn decode_ct(input: &[u8], out: &mut [u8], case: Case) -> Result<(usize, u8), Error> {
    let Some(needed) = decoded_len(input.len()) else {
        return Err(Error::InvalidLength);
    };
    if out.len() < needed {
        return Err(Error::OutputTooSmall);
    }
    let full = input.len() / BLOCK_CHARS;
    let mut chars = [0u8; BLOCK_CHARS];
    let mut bytes = [0u8; BLOCK_BYTES];
    let mut ok = 0xffu8;
    for blk in 0..full {
        for j in 0..BLOCK_CHARS {
            chars[j] = input[blk * BLOCK_CHARS + j];
        }
        ok &= decode_block(&chars, &mut bytes, case);
        for j in 0..BLOCK_BYTES {
            out[blk * BLOCK_BYTES + j] = bytes[j];
        }
    }
    let rest = input.len() - full * BLOCK_CHARS;
    if rest > 0 {
        // Pad with the character for zero, so that the padding is valid
        // and adds no bits.
        chars = [to_char(0, case); BLOCK_CHARS];
        for j in 0..rest {
            chars[j] = input[full * BLOCK_CHARS + j];
        }
        ok &= decode_block(&chars, &mut bytes, case);
        let n = tail_bytes(rest);
        for j in 0..n {
            out[full * BLOCK_BYTES + j] = bytes[j];
        }
        // Canonical form: the bits after the last whole byte are zero.
        // They land in bytes[n], whose other bits come from padding.
        ok &= mask_eq_zero(bytes[n]);
    }
    wipe(&mut chars);
    wipe(&mut bytes);
    // Zero the output if the input was invalid, without a branch.
    for j in 0..needed {
        out[j] &= ok;
    }
    Ok((needed, ok))
}

/// All ones if `x` is zero, else zero.
#[inline(always)]
fn mask_eq_zero(x: u8) -> u8 {
    mask_lt(u16::from(x), 1)
}

/// Overwrites a buffer with zeros in a way the compiler keeps.
#[inline(always)]
fn wipe(buf: &mut [u8]) {
    // An index loop: hax does not extract mutation through `iter_mut`
    // (hax issue 420).
    for i in 0..buf.len() {
        buf[i] = 0;
    }
    // Keeps the stores above from being removed as dead. hax sees only
    // the stores.
    #[cfg(not(hax))]
    core::hint::black_box(&*buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648, section 10, without padding.
    const VECTORS: [(&str, &str); 7] = [
        ("", ""),
        ("f", "MY"),
        ("fo", "MZXQ"),
        ("foo", "MZXW6"),
        ("foob", "MZXW6YQ"),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI"),
    ];

    #[test]
    fn rfc4648_vectors() {
        for (plain, text) in VECTORS {
            let mut enc = [0u8; 16];
            let n = encode(plain.as_bytes(), &mut enc, Case::Upper).unwrap();
            assert_eq!(&enc[..n], text.as_bytes());

            let lower = text.to_ascii_lowercase();
            let n = encode(plain.as_bytes(), &mut enc, Case::Lower).unwrap();
            assert_eq!(&enc[..n], lower.as_bytes());

            let mut dec = [0u8; 16];
            let n = decode(text.as_bytes(), &mut dec, Case::Upper).unwrap();
            assert_eq!(&dec[..n], plain.as_bytes());
            let n = decode(lower.as_bytes(), &mut dec, Case::Lower).unwrap();
            assert_eq!(&dec[..n], plain.as_bytes());
        }
    }

    #[test]
    fn every_character_maps_back() {
        for v in 0u8..32 {
            for case in [Case::Lower, Case::Upper] {
                let c = to_char(v, case);
                assert_eq!(from_char(c, case), (v, 0xff));
            }
        }
        for c in 0u8..=255 {
            let lower = c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c);
            let upper = c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c);
            assert_eq!(from_char(c, Case::Lower).1 == 0xff, lower, "{c}");
            assert_eq!(from_char(c, Case::Upper).1 == 0xff, upper, "{c}");
        }
    }

    #[test]
    fn rejects_bad_input() {
        let mut out = [0u8; 16];
        assert_eq!(
            decode(b"M", &mut out, Case::Upper),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            decode(b"MZX", &mut out, Case::Upper),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            decode(b"MZXW6Y", &mut out, Case::Upper),
            Err(Error::InvalidLength)
        );
        // Wrong case, padding, a digit outside 2 to 7.
        assert_eq!(
            decode(b"my", &mut out, Case::Upper),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(
            decode(b"MY======", &mut out, Case::Upper),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(
            decode(b"M1", &mut out, Case::Upper),
            Err(Error::InvalidEncoding)
        );
        // "MZ" sets unused bits: not canonical, although "MY" decodes.
        assert_eq!(
            decode(b"MZ", &mut out, Case::Upper),
            Err(Error::InvalidEncoding)
        );
    }

    #[test]
    fn rejected_input_leaves_no_output() {
        let mut out = [0xaau8; 10];
        assert_eq!(
            decode(b"MZXW6YT!", &mut out, Case::Upper),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(out[..5], [0u8; 5]);
    }

    #[test]
    fn short_output_is_an_error() {
        let mut out = [0u8; 3];
        assert_eq!(
            encode(b"fo", &mut out, Case::Lower),
            Err(Error::OutputTooSmall)
        );
        let mut out = [0u8; 1];
        assert_eq!(
            decode(b"MZXQ", &mut out, Case::Upper),
            Err(Error::OutputTooSmall)
        );
    }

    #[test]
    fn lengths() {
        assert_eq!(encoded_len(32), Some(52));
        assert_eq!(decoded_len(52), Some(32));
        assert_eq!(encoded_len(usize::MAX), None);
        for n in 0..200 {
            let e = encoded_len(n).unwrap();
            assert_eq!(decoded_len(e), Some(n));
        }
    }

    #[test]
    fn round_trip_all_lengths() {
        let mut data = [0u8; 64];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(151).wrapping_add(7);
        }
        for n in 0..=data.len() {
            let mut enc = [0u8; 110];
            let mut dec = [0u8; 64];
            let e = encode(&data[..n], &mut enc, Case::Lower).unwrap();
            let d = decode(&enc[..e], &mut dec, Case::Lower).unwrap();
            assert_eq!(&dec[..d], &data[..n]);
        }
    }
}

/// Kani proofs. Run with `cargo kani -p mosgird-protocol`.
///
/// Each harness checks every input up to its length bound: no panic, no
/// arithmetic overflow, no out-of-bounds access, and the stated
/// functional property. The bounds cover a full block and every tail
/// length, which is every path through the code.
#[cfg(kani)]
mod proofs {
    use super::*;

    const MAX_BYTES: usize = 11;
    const MAX_CHARS: usize = 18;

    fn any_case() -> Case {
        if kani::any() {
            Case::Lower
        } else {
            Case::Upper
        }
    }

    /// decode(encode(x)) == x, for every x of up to 11 bytes.
    #[kani::proof]
    #[kani::unwind(12)]
    fn encode_then_decode_is_identity() {
        let data: [u8; MAX_BYTES] = kani::any();
        let len: usize = kani::any_where(|&l| l <= MAX_BYTES);
        let case = any_case();
        let mut enc = [0u8; MAX_CHARS];
        let e = encode(&data[..len], &mut enc, case);
        assert!(e.is_ok());
        let e = e.unwrap_or(0);
        let mut dec = [0u8; MAX_BYTES];
        let d = decode(&enc[..e], &mut dec, case);
        assert_eq!(d, Ok(len));
        assert!(dec[..len] == data[..len]);
    }

    /// Any accepted input re-encodes to itself (the decoder accepts only
    /// canonical text), and decoding never panics on any input of up to
    /// 18 characters.
    #[kani::proof]
    #[kani::unwind(19)]
    fn decoder_accepts_only_canonical_text() {
        let text: [u8; MAX_CHARS] = kani::any();
        let len: usize = kani::any_where(|&l| l <= MAX_CHARS);
        let case = any_case();
        let mut dec = [0u8; MAX_BYTES];
        if let Ok(d) = decode(&text[..len], &mut dec, case) {
            let mut enc = [0u8; MAX_CHARS];
            let e = encode(&dec[..d], &mut enc, case);
            assert_eq!(e, Ok(len));
            assert!(enc[..len] == text[..len]);
        }
    }

    /// Any output buffer length is handled without a panic.
    #[kani::proof]
    #[kani::unwind(19)]
    fn short_buffers_do_not_panic() {
        let data: [u8; MAX_BYTES] = kani::any();
        let len: usize = kani::any_where(|&l| l <= MAX_BYTES);
        let out_len: usize = kani::any_where(|&l| l <= MAX_CHARS);
        let mut out = [0u8; MAX_CHARS];
        let _ = encode(&data[..len], &mut out[..out_len], any_case());
        let text: [u8; MAX_CHARS] = kani::any();
        let tlen: usize = kani::any_where(|&l| l <= MAX_CHARS);
        let dlen: usize = kani::any_where(|&l| l <= MAX_BYTES);
        let mut dec = [0u8; MAX_BYTES];
        let _ = decode(&text[..tlen], &mut dec[..dlen], any_case());
    }

    /// The length functions agree for every length.
    #[kani::proof]
    fn lengths_agree() {
        let n: usize = kani::any();
        if let Some(e) = encoded_len(n) {
            assert_eq!(decoded_len(e), Some(n));
        }
    }
}
