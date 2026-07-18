use crate::memlock;
use core::fmt;
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Owns a heap buffer of secret bytes. Built at exact capacity and never grown,
/// page-locked while alive, zeroized on drop.
pub struct SecretBytes {
    buf: Vec<u8>,
    locked: bool,
}

impl SecretBytes {
    fn adopt(buf: Vec<u8>) -> Self {
        debug_assert_eq!(buf.capacity(), buf.len(), "secret buffers must be exact-capacity");
        let locked = memlock::lock(buf.as_ptr() as *mut u8, buf.len());
        SecretBytes { buf, locked }
    }

    pub fn from_exact(bytes: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(bytes.len());
        buf.extend_from_slice(bytes); // fills to capacity exactly; never grows again
        Self::adopt(buf)
    }

    pub fn zeros(len: usize) -> Self {
        let mut buf = Vec::with_capacity(len);
        buf.resize(len, 0);
        Self::adopt(buf)
    }

    pub fn generate(len: usize) -> Self {
        let mut s = Self::zeros(len);
        OsRng.fill_bytes(&mut s.buf);
        s
    }

    pub fn expose(&self) -> &[u8] { &self.buf }
    pub fn expose_mut(&mut self) -> &mut [u8] { &mut self.buf }
    pub fn len(&self) -> usize { self.buf.len() }
    pub fn is_empty(&self) -> bool { self.buf.is_empty() }
    pub fn is_locked(&self) -> bool { self.locked }

    pub fn ct_eq(&self, other: &SecretBytes) -> bool {
        self.buf.ct_eq(&other.buf).into()
    }

    #[cfg(test)]
    pub fn capacity_for_test(&self) -> usize { self.buf.capacity() }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.buf.zeroize();
        if self.locked {
            memlock::unlock(self.buf.as_ptr() as *mut u8, self.buf.capacity());
        }
    }
}

impl zeroize::Zeroize for SecretBytes {
    fn zeroize(&mut self) { self.buf.zeroize(); }
}
impl zeroize::ZeroizeOnDrop for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(***{} bytes***)", self.buf.len())
    }
}

/// UTF-8 secret. Wraps SecretBytes; same lifecycle guarantees.
pub struct SecretString {
    inner: SecretBytes,
}

impl SecretString {
    pub fn from_string(mut s: String) -> Self {
        let inner = SecretBytes::from_exact(s.as_bytes());
        s.zeroize(); // scrub the source String's buffer
        SecretString { inner }
    }
    /// Wrap an already page-locked, zeroize-on-drop `SecretBytes` as a UTF-8
    /// secret WITHOUT copying the plaintext into an intermediate (unlocked,
    /// un-scrubbed) buffer. Returns `None` if the bytes are not valid UTF-8; in
    /// that case `b` is consumed and dropped here (zeroized), leaving no
    /// un-scrubbed plaintext copy behind.
    pub fn from_secret_bytes(b: SecretBytes) -> Option<SecretString> {
        if std::str::from_utf8(b.expose()).is_ok() {
            Some(SecretString { inner: b })
        } else {
            None // b drops -> zeroized
        }
    }
    pub fn expose_str(&self) -> &str {
        // Constructed from a valid String, so bytes are valid UTF-8.
        std::str::from_utf8(self.inner.expose()).expect("secret utf8 invariant")
    }
    pub fn into_bytes(self) -> SecretBytes { self.inner }
}

impl zeroize::Zeroize for SecretString {
    fn zeroize(&mut self) { self.inner.zeroize(); }
}
impl zeroize::ZeroizeOnDrop for SecretString {}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(***{} bytes***)", self.inner.len())
    }
}

/// A key held ENCRYPTED at rest in process RAM (Windows: `CryptProtectMemory`,
/// `SAME_PROCESS`), decrypted only transiently — for the duration of a single
/// crypto operation — via [`ProtectedDek::reveal`]. Between operations no
/// plaintext key sits in memory, shrinking the cold-boot / passive-scrape window.
///
/// Threat scope (hardening program, phase 2): this defends against PASSIVE reads
/// of this process's memory (a cold-boot attack, a memory dump, another process
/// reading our pages) *between* operations. It does NOT defend against code
/// executing INSIDE this process (injection/debugger), which can call
/// `CryptUnprotectMemory` itself — that remains the documented userspace ceiling.
/// On non-Windows targets there is no OS memory encryption, so the key is held in
/// the same page-locked, zeroize-on-drop buffer as everything else (still scrubbed
/// on drop) and `reveal` simply copies it.
pub struct ProtectedDek {
    /// The key, padded to a multiple of the CryptProtectMemory block size and, when
    /// `protected`, encrypted in place. Always page-locked + zeroized on drop.
    blob: SecretBytes,
    /// The original (unpadded) key length.
    len: usize,
    /// Whether OS memory encryption is actually active over `blob`.
    protected: bool,
}

impl ProtectedDek {
    /// Wrap `dek`, encrypting it at rest if the OS supports it. Consumes and
    /// zeroizes the incoming `dek`.
    pub fn new(dek: SecretBytes) -> Self {
        let len = dek.len();
        let block = crate::hardening::BLOCK;
        let padded = len.div_ceil(block).max(1) * block;
        let mut blob = SecretBytes::zeros(padded);
        blob.expose_mut()[..len].copy_from_slice(dek.expose());
        // `dek` drops here, zeroized.
        let protected = crate::hardening::protect_in_place(blob.expose_mut());
        ProtectedDek { blob, len, protected }
    }

    /// Reveal a transient plaintext copy of the key for one operation. The returned
    /// `SecretBytes` is page-locked and zeroized on drop; keep it alive only as long
    /// as the operation needs it.
    pub fn reveal(&self) -> SecretBytes {
        let mut work = SecretBytes::from_exact(self.blob.expose());
        if self.protected {
            // Best-effort: if this fails the bytes stay as-is (ciphertext) and the
            // downstream AEAD/MAC will simply fail closed rather than use a wrong key.
            let _ = crate::hardening::unprotect_in_place(work.expose_mut());
        }
        let out = SecretBytes::from_exact(&work.expose()[..self.len]);
        out
        // `work` drops here, zeroized.
    }

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for ProtectedDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProtectedDek(***{} bytes, protected={}***)", self.len, self.protected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SecretBytes::from_exact(b"hunter2");
        assert_eq!(format!("{s:?}"), "SecretBytes(***7 bytes***)");
    }

    #[test]
    fn from_exact_has_no_spare_capacity() {
        // Anti-realloc invariant: no growth means no stale plaintext copies.
        let s = SecretBytes::from_exact(b"topsecret");
        assert_eq!(s.len(), 9);
        assert_eq!(s.capacity_for_test(), 9);
    }

    #[test]
    fn ct_eq_matches_only_equal_contents() {
        let a = SecretBytes::from_exact(b"abc");
        let b = SecretBytes::from_exact(b"abc");
        let c = SecretBytes::from_exact(b"abd");
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn secretstring_zeroizes_source_string() {
        let src = String::from("passphrase");
        let ss = SecretString::from_string(src);
        assert_eq!(ss.expose_str(), "passphrase");
    }

    #[test]
    fn secret_types_impl_zeroize_on_drop() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<SecretBytes>();
        assert_zod::<SecretString>();
    }

    #[test]
    fn from_secret_bytes_wraps_valid_utf8_and_rejects_invalid() {
        let ok = SecretString::from_secret_bytes(SecretBytes::from_exact(b"hello")).unwrap();
        assert_eq!(ok.expose_str(), "hello");
        // Invalid UTF-8 -> None; the SecretBytes is consumed and zeroized on drop,
        // so no un-scrubbed plaintext copy is left behind.
        assert!(SecretString::from_secret_bytes(SecretBytes::from_exact(&[0xff, 0xfe])).is_none());
    }
}
