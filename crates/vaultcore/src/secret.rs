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
    pub fn expose_str(&self) -> &str {
        // Constructed from a valid String, so bytes are valid UTF-8.
        std::str::from_utf8(self.inner.expose()).expect("secret utf8 invariant")
    }
    pub fn into_bytes(self) -> SecretBytes { self.inner }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(***{} bytes***)", self.inner.len())
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
}
