//! Windows Hello as an OPT-IN, additional user-presence gate on the REVEAL
//! action (see `main.rs`'s `on_reveal`, gated by `Prefs::hello_enabled`). It
//! is never app-entry and never contributes to the KEK: it does not touch
//! unlock at all. If Hello is unavailable or the user declines the prompt,
//! reveal simply does not proceed for that click -- the passphrase (+ TPM, if
//! bound) remains the sole cryptographic factor, unchanged either way.

#[cfg(windows)]
pub fn available() -> bool {
    use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerifierAvailability};
    match UserConsentVerifier::CheckAvailabilityAsync().and_then(|op| op.get()) {
        Ok(a) => a == UserConsentVerifierAvailability::Available,
        Err(_) => false,
    }
}

#[cfg(windows)]
pub fn verify(message: &str) -> bool {
    use windows::core::HSTRING;
    use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerificationResult};
    let msg = HSTRING::from(message);
    match UserConsentVerifier::RequestVerificationAsync(&msg).and_then(|op| op.get()) {
        Ok(r) => r == UserConsentVerificationResult::Verified,
        Err(_) => false,
    }
}

#[cfg(not(windows))]
pub fn available() -> bool {
    false
}
#[cfg(not(windows))]
pub fn verify(_message: &str) -> bool {
    false
}
