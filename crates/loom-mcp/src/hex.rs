//! Fixed-width hexadecimal decoding for key and signature material.
//!
//! Ed25519 public keys and signatures reach `loomd` as text — a mounted key file, a JSON-RPC
//! argument — and every one of them has a known length. Decoding is therefore length-checked first:
//! a value that is not exactly `N` bytes of lowercase-or-uppercase hex is refused before any
//! cryptographic API sees it, so a truncated mount or a half-copied argument fails as *malformed
//! input* rather than as a signature that happens not to verify.

/// Decode exactly `N` bytes from `2 * N` hexadecimal characters.
///
/// Surrounding whitespace is trimmed, because a key file written by an operator or a secret manager
/// commonly ends in a newline. Nothing else is accepted: no `0x` prefix, no separators, no partial
/// value.
pub fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.trim();
    if text.len() != N * 2 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(pair).ok()?;
        out[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::decode_hex;

    #[test]
    fn decodes_an_exact_width_value() {
        assert_eq!(decode_hex::<2>("00ff"), Some([0x00, 0xff]));
        assert_eq!(decode_hex::<2>("00FF"), Some([0x00, 0xff]));
    }

    #[test]
    fn trims_the_trailing_newline_a_key_file_carries() {
        assert_eq!(decode_hex::<2>("00ff\n"), Some([0x00, 0xff]));
    }

    #[test]
    fn refuses_anything_that_is_not_exactly_n_bytes_of_hex() {
        assert_eq!(decode_hex::<2>("00f"), None, "too short");
        assert_eq!(decode_hex::<2>("00ff00"), None, "too long");
        assert_eq!(decode_hex::<2>("0x00"), None, "prefixed");
        assert_eq!(decode_hex::<2>("00:ff"), None, "separated");
        assert_eq!(decode_hex::<2>("00gg"), None, "not hex");
    }
}
