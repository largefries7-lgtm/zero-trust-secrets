//! Windows Hello as an ADDITIONAL user-presence gate. It gates access to the app
//! (or a reveal); it does NOT contribute to the KEK and never blocks a passphrase
//! unlock. If Hello is unavailable or declined, the app still unlocks via the
//! passphrase factor (the real cryptographic factor is unchanged).

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
