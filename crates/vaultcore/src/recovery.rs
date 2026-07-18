//! Generated recovery code for the optional single-factor escrow.
//!
//! Instead of a human-chosen recovery *passphrase* (whose strength collapses a
//! stolen vault to whatever the human picked), the escrow is unlocked by a
//! system-generated **128-bit** code — as strong as the DEK itself. The code is
//! shown once at creation for the user to store offline (à la a BitLocker /
//! 1Password recovery key). It is encoded in **Crockford base32** (upper-case,
//! excludes the ambiguous I/L/O/U) grouped into 4-char blocks for transcription.
//!
//! The code's *canonical* form (26 chars, no separators) is what wraps the DEK via
//! the existing `envelope::wrap_dek_recovery` — no new cryptography. A single
//! `normalize()` is applied on both generation and unlock, so spacing, dashes and
//! case in what the user types never matter, and an accidental `O`-for-`0` (etc.)
//! transcription is corrected.

use crate::secret::{SecretBytes, SecretString};

/// Crockford base32 alphabet (no I, L, O, U). 32 symbols = 5 bits each.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Bits of entropy in a generated code.
pub const CODE_BITS: usize = 128;

/// A recovery code held as a page-locked, zeroize-on-drop secret in its canonical
/// (separator-free, upper-case) form.
pub struct RecoveryCode {
    canonical: SecretString,
}

impl RecoveryCode {
    /// Generate a fresh 128-bit code from the OS CSPRNG.
    pub fn generate() -> Self {
        let raw = SecretBytes::generate(CODE_BITS / 8); // 16 bytes
        let canonical = crockford_encode(raw.expose());
        // `from_string` zeroizes the transient `String`; `raw` zeroizes on drop.
        RecoveryCode { canonical: SecretString::from_string(canonical) }
    }

    /// Parse whatever the user typed into the canonical form (case/dashes/spaces
    /// tolerated; ambiguous O/I/L corrected to 0/1/1).
    pub fn from_user_input(input: &str) -> Self {
        RecoveryCode { canonical: SecretString::from_string(normalize(input)) }
    }

    /// The canonical secret to feed to `wrap_dek_recovery` / `unwrap_dek_recovery`.
    pub fn secret(&self) -> &SecretString {
        &self.canonical
    }

    /// Human-facing grouped form, e.g. `A1B2-C3D4-...`. This is secret material —
    /// the caller displays it once and must not persist it.
    pub fn display(&self) -> String {
        let s = self.canonical.expose_str();
        let mut out = String::with_capacity(s.len() + s.len() / 4);
        for (i, c) in s.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }
}

/// Encode bytes as Crockford base32 (no padding). For 16 bytes this yields 26
/// chars (128 bits / 5, rounded up).
fn crockford_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((buffer >> bits) & 0x1f) as usize] as char);
        }
        // Drop the just-consumed high bits so `buffer` never overflows a u32.
        buffer &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(CROCKFORD[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Normalize user input to the canonical alphabet: upper-case, drop anything that
/// is not a Crockford symbol (spaces, dashes, junk), and correct the ambiguous
/// letters O→0, I→1, L→1 (Crockford's own aliasing).
fn normalize(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        let mapped = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        if CROCKFORD.contains(&(mapped as u8)) {
            out.push(mapped);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_canonical_and_display_is_grouped() {
        let code = RecoveryCode::generate();
        let canon = code.secret().expose_str().to_string();
        // 128 bits / 5 bits-per-char, rounded up = 26 chars.
        assert_eq!(canon.chars().count(), 26);
        assert!(canon.chars().all(|c| CROCKFORD.contains(&(c as u8))));
        let shown = code.display();
        assert!(shown.contains('-'));
        // Stripping the dashes recovers the canonical form.
        assert_eq!(normalize(&shown), canon);
    }

    #[test]
    fn user_input_round_trips_through_formatting_noise() {
        let code = RecoveryCode::generate();
        let shown = code.display();
        // Lower-cased, with extra spaces — must normalize back to the same secret.
        let noisy = format!("  {}  ", shown.to_lowercase());
        let parsed = RecoveryCode::from_user_input(&noisy);
        assert_eq!(parsed.secret().expose_str(), code.secret().expose_str());
    }

    #[test]
    fn ambiguous_letters_are_corrected() {
        // A canonical code can contain 0 and 1; typing O/o and I/l must still match.
        // "O0Il-1L0o" -> O→0,0→0,I→1,l→1,(dash dropped),1→1,L→1,0→0,o→0 = "00111100".
        let parsed = RecoveryCode::from_user_input("O0Il-1L0o");
        assert_eq!(parsed.secret().expose_str(), "00111100");
    }

    #[test]
    fn distinct_codes_differ() {
        let a = RecoveryCode::generate();
        let b = RecoveryCode::generate();
        assert_ne!(a.secret().expose_str(), b.secret().expose_str());
    }

    #[test]
    fn crockford_encode_is_stable_and_sized() {
        assert_eq!(crockford_encode(&[0u8; 16]).chars().count(), 26);
        assert_eq!(crockford_encode(&[0u8; 16]), "0".repeat(26));
        assert_eq!(crockford_encode(&[0xff; 16]).chars().count(), 26);
    }
}
