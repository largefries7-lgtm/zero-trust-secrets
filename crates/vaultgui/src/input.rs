//! Field → secret marshalling, and an HONEST statement of the residual.
//!
//! What we control: as soon as a secret leaves a text field we move it into a
//! page-locked `SecretString` via `drain_to_secret`, which zeroizes the source
//! `String` we own, and we set the Slint field's text to empty.
//!
//! What we CANNOT scrub (documented, not hidden — spec invariant #4):
//!   * Slint's `LineEdit` keeps the edited text in an internal `SharedString`.
//!     Editing may have reallocated that buffer, leaving prior un-zeroized heap
//!     copies; clearing the field drops the current buffer but cannot zeroize
//!     past copies, and Slint owns the glyph/layout caches.
//!   * The OS text stack (IME composition, edit undo) may retain copies outside
//!     our address space entirely.
//! The `gui-post-autolock` harness scenario measures what actually survives.

use vaultcore::secret::SecretString;

/// Move `buf`'s contents into a `SecretString`, leaving `buf` empty and its
/// heap buffer zeroized. `SecretString::from_string` zeroizes the `String` it
/// consumes; `std::mem::take` hands it that owned buffer while resetting `buf`.
pub fn drain_to_secret(buf: &mut String) -> SecretString {
    SecretString::from_string(std::mem::take(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moves_text_and_empties_source() {
        let mut field = String::from("hunter2");
        let secret = drain_to_secret(&mut field);
        assert_eq!(secret.expose_str(), "hunter2");
        assert!(field.is_empty());
    }

    #[test]
    fn empty_field_yields_empty_secret() {
        let mut field = String::new();
        let secret = drain_to_secret(&mut field);
        assert_eq!(secret.expose_str(), "");
    }
}
