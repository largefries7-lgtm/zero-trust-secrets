//! CSPRNG password generator with modulo-bias-free rejection sampling.
//!
//! Builds the password directly in a page-locked, zeroize-on-drop `SecretBytes`
//! (never an ordinary `String`), then wraps it in place as a `SecretString`.
//! Lifted verbatim from `vaultctl` so the CLI and GUI share one tested generator.

use crate::secret::{SecretBytes, SecretString};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?";

/// Generate a password of `len` chars. Returns the secret and the charset size
/// `n` (so callers can report `len * log2(n)` bits of entropy honestly).
pub fn generate_password(len: usize, symbols: bool) -> (SecretString, usize) {
    let mut charset: Vec<u8> = Vec::new();
    charset.extend_from_slice(LOWER);
    charset.extend_from_slice(UPPER);
    charset.extend_from_slice(DIGITS);
    if symbols {
        charset.extend_from_slice(SYMBOLS);
    }
    let n = charset.len();
    let threshold = (256 / n) * n;

    let mut out = SecretBytes::zeros(len);
    let mut filled = 0usize;
    while filled < len {
        let need = len - filled;
        let batch = SecretBytes::generate(need.saturating_mul(2).max(16));
        for &b in batch.expose() {
            if filled == len {
                break;
            }
            let b = b as usize;
            if b < threshold {
                out.expose_mut()[filled] = charset[b % n];
                filled += 1;
            }
        }
    }
    let secret = SecretString::from_secret_bytes(out)
        .expect("generated password is ASCII (valid UTF-8)");
    (secret, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_and_charset_size_default_alnum() {
        let (pw, n) = generate_password(24, false);
        assert_eq!(pw.expose_str().chars().count(), 24);
        assert_eq!(n, 62);
        assert!(pw.expose_str().chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn symbols_expand_charset() {
        let (pw, n) = generate_password(40, true);
        assert_eq!(pw.expose_str().chars().count(), 40);
        assert_eq!(n, 62 + SYMBOLS.len());
    }

    #[test]
    fn zero_length_is_empty() {
        let (pw, _) = generate_password(0, false);
        assert_eq!(pw.expose_str(), "");
    }
}
