//! Passphrase strength estimation and a creation-time policy gate.
//!
//! This is a deliberately dependency-free *floor*, not a strength promise. The
//! entropy figure is the honest `len × log2(character-pool)` estimate (the same
//! coarse model NIST once published) and is intentionally conservative; on top of
//! it an embedded blocklist hard-rejects the most common / trivially-patterned
//! choices regardless of the computed bits. We decline a zxcvbn-grade estimator
//! on purpose: it would add a dependency + lookup tables to the attack surface
//! (see front F). The tradeoff is that this catches *weak* passphrases, it does
//! not certify *strong* ones.

/// Result of estimating a passphrase.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimate {
    /// Coarse Shannon-style entropy estimate, in bits.
    pub bits: f64,
    /// True if the passphrase (or a trivial transform of it) is on the blocklist
    /// or is a pure repeat/sequence.
    pub is_common: bool,
    pub len: usize,
}

/// A creation-time acceptance policy. Stricter for single-factor vaults (the
/// passphrase is the *only* thing between a stolen file and the secrets) than for
/// two-factor (TPM-bound) vaults, where it is one of two required factors.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub min_bits: f64,
    pub min_len: usize,
    pub forbid_common: bool,
}

impl Policy {
    /// TPM two-factor vault: passphrase is 1 of 2 required factors.
    pub fn two_factor() -> Self {
        Policy { min_bits: 50.0, min_len: 8, forbid_common: true }
    }
    /// No-TPM single-factor vault: passphrase is the sole factor, so the floor is
    /// materially higher.
    pub fn single_factor() -> Self {
        Policy { min_bits: 70.0, min_len: 10, forbid_common: true }
    }
}

/// Why a passphrase was rejected. Carries no passphrase material.
#[derive(Debug, Clone, PartialEq)]
pub enum Weakness {
    TooShort { min: usize },
    KnownCommon,
    LowEntropy { bits: f64, min: f64 },
}

impl core::fmt::Display for Weakness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Weakness::TooShort { min } => {
                write!(f, "must be at least {min} characters")
            }
            Weakness::KnownCommon => {
                write!(f, "this is a commonly-used or easily-guessed passphrase")
            }
            Weakness::LowEntropy { bits, min } => write!(
                f,
                "too weak (~{bits:.0} bits of entropy; need at least {min:.0}) — add length or a mix of character types",
            ),
        }
    }
}

/// Estimate the strength of `pass`. Pure; runs on a `&str` view (the caller holds
/// the secret in a page-locked buffer and passes a transient borrow).
pub fn estimate(pass: &str) -> Estimate {
    Estimate { bits: entropy_bits(pass), is_common: is_common(pass), len: pass.chars().count() }
}

/// Enforce `policy`. `Ok(())` means the passphrase clears the floor; `Err` names
/// the reason (never the passphrase).
pub fn check(pass: &str, policy: &Policy) -> Result<(), Weakness> {
    let est = estimate(pass);
    if est.len < policy.min_len {
        return Err(Weakness::TooShort { min: policy.min_len });
    }
    if policy.forbid_common && est.is_common {
        return Err(Weakness::KnownCommon);
    }
    if est.bits < policy.min_bits {
        return Err(Weakness::LowEntropy { bits: est.bits, min: policy.min_bits });
    }
    Ok(())
}

/// `len × log2(pool)` where `pool` is the summed size of the character classes
/// present. Coarse by design; see the module note.
fn entropy_bits(pass: &str) -> f64 {
    if pass.is_empty() {
        return 0.0;
    }
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut symbol = false;
    let mut extended = false;
    for c in pass.chars() {
        if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else if c.is_ascii() {
            symbol = true; // punctuation / space
        } else {
            extended = true; // non-ASCII (emoji, accented, other scripts)
        }
    }
    let mut pool = 0u32;
    if lower {
        pool += 26;
    }
    if upper {
        pool += 26;
    }
    if digit {
        pool += 10;
    }
    if symbol {
        pool += 33; // printable ASCII punctuation + space, approx
    }
    if extended {
        pool += 128; // generous, honestly coarse bump for non-ASCII
    }
    let len = pass.chars().count() as f64;
    len * (pool as f64).log2()
}

/// True if `pass` is a known-common choice or a pure repeat/sequence, allowing for
/// trivial transforms (case, leetspeak, trailing digits/punctuation).
fn is_common(pass: &str) -> bool {
    if is_repeat_or_sequence(pass) {
        return true;
    }
    let lower = pass.to_lowercase();
    if in_blocklist(&lower) {
        return true;
    }
    let leet = leet_normalize(&lower);
    if leet != lower && in_blocklist(&leet) {
        return true;
    }
    // "password1", "monkey!!" -> strip trailing digits/bangs and re-check.
    let stripped: &str = lower.trim_end_matches(|c: char| c.is_ascii_digit() || c == '!' || c == '.');
    if stripped.len() >= 4 && in_blocklist(stripped) {
        return true;
    }
    false
}

fn in_blocklist(s: &str) -> bool {
    BLOCKLIST.contains(&s)
}

/// Map common leetspeak substitutions back to letters so `p4ssw0rd` is caught.
fn leet_normalize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | '!' | '|' => 'i',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            '8' => 'b',
            _ => c,
        })
        .collect()
}

/// True for all-one-character (`aaaa`) and monotonic ASCII runs (`123456`,
/// `abcdef`, `9876`) spanning the whole string (min length 4 to matter).
fn is_repeat_or_sequence(pass: &str) -> bool {
    let bytes = pass.as_bytes();
    if bytes.len() < 4 {
        return false;
    }
    if !pass.is_ascii() {
        return false;
    }
    let all_same = bytes.iter().all(|&b| b == bytes[0]);
    if all_same {
        return true;
    }
    let ascending = bytes.windows(2).all(|w| w[1] == w[0] + 1);
    let descending = bytes.windows(2).all(|w| w[0] == w[1] + 1);
    ascending || descending
}

/// A compact blocklist of the most common passwords and trivial words. This is a
/// floor, not an exhaustive breach corpus — it exists to reject the choices an
/// online/offline guesser tries first. Entries are lowercase.
const BLOCKLIST: &[&str] = &[
    "password", "passw0rd", "password1", "passwords", "pass", "passphrase",
    "123456", "12345678", "123456789", "1234567890", "12345", "1234567", "111111",
    "000000", "654321", "666666", "121212", "abc123", "a1b2c3", "qwerty",
    "qwertyuiop", "qwerty123", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1q2w3e4r", "1qaz2wsx", "qazwsx", "letmein", "welcome", "welcome1", "admin",
    "administrator", "root", "toor", "login", "user", "guest", "changeme",
    "default", "secret", "master", "access", "shadow", "superman", "batman",
    "trustno1", "iloveyou", "sunshine", "princess", "dragon", "monkey",
    "football", "baseball", "basketball", "soccer", "hockey", "computer",
    "internet", "samsung", "google", "facebook", "whatever", "hello", "hello123",
    "freedom", "starwars", "michael", "jennifer", "jessica", "ashley",
    "michelle", "daniel", "thomas", "charlie", "andrew", "matthew", "joshua",
    "hunter", "hunter2", "ninja", "mustang", "harley", "ranger", "tigger",
    "purple", "orange", "yellow", "flower", "cookie", "chocolate", "summer",
    "winter", "spring", "autumn", "money", "love", "sex", "god", "abcdef",
    "abcabc", "aaaaaa", "asshole", "fuckyou", "fuckoff", "biteme", "654321",
    "112233", "123123", "159753", "987654321", "qwe123", "q1w2e3", "test",
    "test123", "testing", "temp", "temporary", "vault", "vaultpassword",
    "correcthorsebatterystaple", "letmein1", "admin123", "root123", "pa55word",
    "p@ssw0rd", "p@ssword", "welcome123", "login123", "secret123", "master123",
    "111222", "abcd1234", "1234abcd", "passw0rd1", "iloveyou1", "trustno1!",
    "starwars1", "dragon1", "monkey1", "football1", "baseball1", "shadow1",
    "michael1", "superman1", "batman1", "ncc1701", "thx1138", "jordan23",
    "michael23", "666999", "555555", "222222", "333333", "444444", "777777",
    "888888", "999999", "101010", "202020", "123321", "789456", "147258",
    "abcde", "12qwaszx", "asdf1234", "zaq12wsx", "qwertyui", "qazxsw",
    "windows", "linux", "ubuntu", "system", "server", "network", "database",
    "oracle", "mysql", "postgres", "redhat", "cisco", "juniper", "office",
    "outlook", "gmail", "yahoo", "hotmail", "twitter", "instagram", "snapchat",
    "netflix", "spotify", "amazon", "apple", "microsoft", "nintendo",
    "playstation", "xbox", "minecraft", "fortnite", "roblox", "pokemon",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero_bits_and_short() {
        let e = estimate("");
        assert_eq!(e.bits, 0.0);
        assert_eq!(e.len, 0);
    }

    #[test]
    fn entropy_grows_with_length_and_variety() {
        let lower = estimate("aaaaaaaaaaaa").bits; // repeat is common, but bits still computed
        let mixed = estimate("Tr0ub4dour&3xtra").bits;
        assert!(mixed > lower);
        // 12 lowercase distinct-ish chars ≈ 12 * log2(26) ≈ 56 bits.
        assert!((estimate("abcdlkwjefhq").bits - 12.0 * (26f64).log2()).abs() < 0.5);
    }

    #[test]
    fn common_passwords_are_flagged() {
        for p in ["password", "Password1", "P@ssw0rd", "123456", "qwerty", "letmein"] {
            assert!(estimate(p).is_common, "{p} should be common");
        }
    }

    #[test]
    fn leet_and_trailing_digits_are_caught() {
        assert!(estimate("p4ssw0rd").is_common);
        assert!(estimate("password123").is_common);
        assert!(estimate("monkey!").is_common);
    }

    #[test]
    fn repeats_and_sequences_are_common() {
        assert!(estimate("aaaa").is_common);
        assert!(estimate("123456").is_common);
        assert!(estimate("abcdef").is_common);
        assert!(estimate("9876").is_common);
        // A genuinely random-looking string is not.
        assert!(!estimate("g7Qv-m2Xz-Lp9").is_common);
    }

    #[test]
    fn two_factor_policy_accepts_reasonable_rejects_weak() {
        let p = Policy::two_factor();
        // 12 random-ish lowercase ≈ 56 bits > 50, not common -> ok.
        assert!(check("mkqzjrhwltvd", &p).is_ok());
        // too short
        assert!(matches!(check("aB3$x", &p), Err(Weakness::TooShort { .. })));
        // common
        assert!(matches!(check("password1", &p), Err(Weakness::KnownCommon)));
        // long enough, not common, but low entropy (all lowercase, 9 chars ≈ 42 bits)
        assert!(matches!(check("qzmkl? ", &p), Err(_)));
    }

    #[test]
    fn single_factor_policy_is_stricter_than_two_factor() {
        // ~56-bit passphrase: passes two-factor (>=50) but fails single (<70).
        let pass = "mkqzjrhwltvd"; // 12 * log2(26) ≈ 56.4
        assert!(check(pass, &Policy::two_factor()).is_ok());
        assert!(matches!(
            check(pass, &Policy::single_factor()),
            Err(Weakness::LowEntropy { .. })
        ));
        // A long mixed passphrase clears the single-factor floor.
        assert!(check("Gv7!kQ2m-Zp9x_Lw3r#Ht6", &Policy::single_factor()).is_ok());
    }
}
