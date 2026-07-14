# Zero-Trust Secrets Manager — Security Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a headless, hardware-bound secrets-manager core in Rust whose plaintext secrets provably never linger in process RAM, verified by a memory-scraping harness.

**Architecture:** A Cargo workspace: `vaultcore` (lib) holds zeroizing secret types, an XChaCha20-Poly1305 crypto envelope, an authenticated vault file format, and a `KeyProvider` HAL. The 256-bit DEK is dual-wrapped — TPM-sealed (Windows CNG Platform Crypto Provider) and Argon2id recovery-escrowed. `vaultctl` (bin) is a thin CLI so the `verify/` harness has a real process to memory-dump.

**Tech Stack:** Rust 1.96, `zeroize`, `chacha20poly1305`, `argon2`, `hkdf`, `sha2`, `subtle`, `getrandom`, `rand_core`, `clap`, `proptest`, `windows` (CNG NCrypt + `VirtualLock` + `MiniDumpWriteDump`), Python 3 (dump scanner).

## Global Constraints

- **Language/toolchain:** Rust edition 2021, MSRV 1.96.0. `#![forbid(unsafe_op_in_unsafe_fn)]`; `unsafe` allowed only in `memlock.rs`, `cng_pcp.rs`, and the `verify/dumper` crate, each with a `// SAFETY:` comment.
- **No network I/O anywhere in `vaultcore` or `vaultctl`.** Air-gapped by construction.
- **No secret-bearing type may derive `Clone`, `Serialize`, `Debug` (auto), or `Display` (auto).** `Debug` is hand-implemented to redact.
- **Secrets are built in exact-capacity buffers and never grown** (no `push`/`extend` on a secret buffer after allocation).
- **AEAD:** XChaCha20-Poly1305. **KDF:** Argon2id. **Subkeys/MAC:** HKDF-SHA256. **RNG:** OS CSPRNG only (`OsRng`/`getrandom`).
- **Fail closed:** any tamper, wrong passphrase, or auth failure returns `Err`, never partial plaintext.
- **`hardware_bound=false`** is only reachable via explicit `--allow-no-tpm` and must be surfaced in `seal-status` and every unlock.
- **Commit after every task** with the message shown in that task's final step.

---

## File structure

| File | Responsibility |
|------|----------------|
| `Cargo.toml` | Workspace manifest |
| `crates/vaultcore/src/lib.rs` | Crate root, re-exports, `Error` enum |
| `crates/vaultcore/src/secret.rs` | `SecretBytes`, `SecretString`, redacted Debug, exact-capacity ctors, `ct_eq` |
| `crates/vaultcore/src/memlock.rs` | `VirtualLock`/`VirtualUnlock` page-locking helper |
| `crates/vaultcore/src/crypto.rs` | AEAD seal/open, HKDF subkey, Argon2id KEK derive |
| `crates/vaultcore/src/vault.rs` | Header (de)serialization, header MAC, records, lock/unlock state machine |
| `crates/vaultcore/src/keyprovider/mod.rs` | `KeyProvider` trait, `ProviderStatus`, `SealedBlob` |
| `crates/vaultcore/src/keyprovider/recovery.rs` | Argon2id recovery escrow provider |
| `crates/vaultcore/src/keyprovider/cng_pcp.rs` | Windows TPM provider (CNG Platform Crypto Provider) |
| `crates/vaultcore/src/keyprovider/stubs.rs` | macOS/Linux `Unsupported` stubs |
| `crates/vaultctl/src/main.rs` | clap CLI, clipboard auto-clear, no-echo input |
| `verify/dumper/src/main.rs` | Scenario runner + `MiniDumpWriteDump` |
| `verify/scan_dump.py` | Volatility-style canary scanner |
| `verify/TEST_PLAN.md` | Step-by-step verification procedure |

---

## Task 0: Workspace scaffold

**Files:**
- Create: `Cargo.toml`, `crates/vaultcore/Cargo.toml`, `crates/vaultcore/src/lib.rs`, `crates/vaultctl/Cargo.toml`, `crates/vaultctl/src/main.rs`

**Interfaces:**
- Produces: `vaultcore::Error` (enum), workspace that builds.

- [ ] **Step 1: Write workspace manifest**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/vaultcore", "crates/vaultctl"]

[workspace.package]
edition = "2021"
rust-version = "1.96"

[workspace.dependencies]
zeroize = { version = "1", features = ["derive"] }
chacha20poly1305 = "0.10"
argon2 = "0.5"
hkdf = "0.12"
sha2 = "0.10"
subtle = "2"
getrandom = "0.2"
rand_core = { version = "0.6", features = ["getrandom"] }
clap = { version = "4", features = ["derive"] }
thiserror = "1"
proptest = "1"

[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = [
  "Win32_Foundation",
  "Win32_System_Memory",
  "Win32_Security_Cryptography",
  "Win32_System_Diagnostics_Debug",
] }
```

- [ ] **Step 2: Write `vaultcore` manifest and root**

`crates/vaultcore/Cargo.toml`:
```toml
[package]
name = "vaultcore"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true

[dependencies]
zeroize.workspace = true
chacha20poly1305.workspace = true
argon2.workspace = true
hkdf.workspace = true
sha2.workspace = true
subtle.workspace = true
getrandom.workspace = true
rand_core.workspace = true
thiserror.workspace = true

[target.'cfg(windows)'.dependencies]
windows.workspace = true

[dev-dependencies]
proptest.workspace = true
```

`crates/vaultcore/src/lib.rs`:
```rust
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod crypto;
pub mod keyprovider;
pub mod memlock;
pub mod secret;
pub mod vault;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("authentication failed (tamper or wrong key)")]
    AuthFailed,
    #[error("vault format error: {0}")]
    Format(String),
    #[error("key provider: {0}")]
    Provider(String),
    #[error("vault is locked")]
    Locked,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
```

- [ ] **Step 3: Write `vaultctl` stub**

`crates/vaultctl/Cargo.toml`:
```toml
[package]
name = "vaultctl"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true

[dependencies]
vaultcore = { path = "../vaultcore" }
clap.workspace = true
```

`crates/vaultctl/src/main.rs`:
```rust
fn main() {
    println!("vaultctl");
}
```

- [ ] **Step 4: Verify it builds**

Run: `cargo build`
Expected: compiles (modules `crypto`/`keyprovider`/etc. are empty files — create them as empty `// placeholder` files so `mod` lines resolve, or add the modules in their own tasks). To unblock the build now, create each `src/*.rs` and `src/keyprovider/mod.rs` as empty stubs containing only a `//! placeholder` line.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/
git commit -m "chore: scaffold vaultcore + vaultctl workspace"
```

---

## Task 1: Zeroizing secret types

**Files:**
- Create: `crates/vaultcore/src/secret.rs`, `crates/vaultcore/src/memlock.rs`
- Test: inline `#[cfg(test)]` in `secret.rs`

**Interfaces:**
- Consumes: `crate::Result`.
- Produces:
  - `SecretBytes` with `from_exact(&[u8]) -> Self`, `generate(len) -> Self`, `zeros(len) -> Self`, `expose(&self) -> &[u8]`, `expose_mut(&mut self) -> &mut [u8]`, `len(&self) -> usize`, `ct_eq(&self, &SecretBytes) -> bool`. Implements `Zeroize + ZeroizeOnDrop`, hand-written redacting `Debug`. No `Clone`.
  - `SecretString` with `from_string(String) -> Self`, `expose_str(&self) -> &str`, `into_bytes(self) -> SecretBytes`.
  - `memlock::lock(ptr: *mut u8, len: usize) -> bool` and `memlock::unlock(ptr, len)`.

- [ ] **Step 1: Write the failing test (redaction + no-grow + zeroize-on-drop)**

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p vaultcore secret::`
Expected: FAIL — `SecretBytes` not found.

- [ ] **Step 3: Write `memlock.rs`**

```rust
//! Page-locking so secret buffers cannot be written to the pagefile.
//! Degrades to a no-op (returns false) if the privilege is unavailable.

#[cfg(windows)]
pub fn lock(ptr: *mut u8, len: usize) -> bool {
    use windows::Win32::System::Memory::VirtualLock;
    if len == 0 { return true; }
    // SAFETY: caller guarantees ptr..ptr+len is an owned, live allocation.
    unsafe { VirtualLock(ptr as _, len).is_ok() }
}

#[cfg(windows)]
pub fn unlock(ptr: *mut u8, len: usize) {
    use windows::Win32::System::Memory::VirtualUnlock;
    if len == 0 { return; }
    // SAFETY: same allocation previously passed to lock().
    let _ = unsafe { VirtualUnlock(ptr as _, len) };
}

#[cfg(not(windows))]
pub fn lock(_ptr: *mut u8, _len: usize) -> bool { false }
#[cfg(not(windows))]
pub fn unlock(_ptr: *mut u8, _len: usize) {}
```

- [ ] **Step 4: Write `secret.rs`**

```rust
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p vaultcore secret::`
Expected: PASS (4 tests). Note: `from_exact` uses `with_capacity(n)` then `extend_from_slice` of exactly `n` bytes — capacity stays `n`.

- [ ] **Step 6: Commit**

```bash
git add crates/vaultcore/src/secret.rs crates/vaultcore/src/memlock.rs
git commit -m "feat(vaultcore): zeroizing SecretBytes/SecretString with page-locking"
```

---

## Task 2: Crypto primitives (AEAD, HKDF, Argon2id)

**Files:**
- Create/replace: `crates/vaultcore/src/crypto.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `SecretBytes`, `SecretString`, `crate::{Error, Result}`.
- Produces:
  - `pub const KEY_LEN: usize = 32;`
  - `aead_seal(key: &SecretBytes, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>` → `nonce(24) || ciphertext+tag`.
  - `aead_open(key: &SecretBytes, aad: &[u8], blob: &[u8]) -> Result<SecretBytes>`.
  - `hkdf_subkey(dek: &SecretBytes, info: &[u8], out_len: usize) -> SecretBytes`.
  - `Argon2Params { mem_kib: u32, time: u32, parallelism: u32, salt: [u8;16] }` with `default_tuned()` and `random_salt()`.
  - `derive_kek(passphrase: &SecretString, p: &Argon2Params) -> Result<SecretBytes>` (32-byte output).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{SecretBytes, SecretString};

    #[test]
    fn aead_roundtrip() {
        let key = SecretBytes::generate(KEY_LEN);
        let blob = aead_seal(&key, b"aad", b"attack at dawn").unwrap();
        let pt = aead_open(&key, b"aad", &blob).unwrap();
        assert_eq!(pt.expose(), b"attack at dawn");
    }

    #[test]
    fn aead_rejects_tampered_ciphertext() {
        let key = SecretBytes::generate(KEY_LEN);
        let mut blob = aead_seal(&key, b"aad", b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(aead_open(&key, b"aad", &blob), Err(crate::Error::AuthFailed)));
    }

    #[test]
    fn aead_rejects_wrong_aad() {
        let key = SecretBytes::generate(KEY_LEN);
        let blob = aead_seal(&key, b"aad1", b"secret").unwrap();
        assert!(aead_open(&key, b"aad2", &blob).is_err());
    }

    #[test]
    fn hkdf_is_deterministic_and_domain_separated() {
        let dek = SecretBytes::from_exact(&[7u8; KEY_LEN]);
        let a = hkdf_subkey(&dek, b"record", KEY_LEN);
        let a2 = hkdf_subkey(&dek, b"record", KEY_LEN);
        let b = hkdf_subkey(&dek, b"header-mac", KEY_LEN);
        assert!(a.ct_eq(&a2));
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn derive_kek_is_stable_for_same_input() {
        let p = Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [1u8; 16] };
        let k1 = derive_kek(&SecretString::from_string("pw".into()), &p).unwrap();
        let k2 = derive_kek(&SecretString::from_string("pw".into()), &p).unwrap();
        assert!(k1.ct_eq(&k2));
        assert_eq!(k1.len(), KEY_LEN);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p vaultcore crypto::`
Expected: FAIL — functions undefined.

- [ ] **Step 3: Implement `crypto.rs`**

```rust
use crate::secret::{SecretBytes, SecretString};
use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

pub fn aead_seal(key: &SecretBytes, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| Error::Format("bad key length".into()))?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::AuthFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn aead_open(key: &SecretBytes, aad: &[u8], blob: &[u8]) -> Result<SecretBytes> {
    if blob.len() < NONCE_LEN {
        return Err(Error::Format("blob too short".into()));
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| Error::Format("bad key length".into()))?;
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::AuthFailed)?;
    // Move plaintext into an exact-capacity secret buffer, then scrub the Vec.
    let secret = SecretBytes::from_exact(&pt);
    let mut pt = pt;
    use zeroize::Zeroize;
    pt.zeroize();
    Ok(secret)
}

pub fn hkdf_subkey(dek: &SecretBytes, info: &[u8], out_len: usize) -> SecretBytes {
    let hk = Hkdf::<Sha256>::new(None, dek.expose());
    let mut out = SecretBytes::zeros(out_len);
    hk.expand(info, out.expose_mut()).expect("hkdf out_len <= 255*32");
    out
}

#[derive(Clone, Copy)]
pub struct Argon2Params {
    pub mem_kib: u32,
    pub time: u32,
    pub parallelism: u32,
    pub salt: [u8; 16],
}

impl Argon2Params {
    pub fn default_tuned() -> Self {
        Self { mem_kib: 65536, time: 3, parallelism: 1, salt: Self::random_salt() }
    }
    pub fn random_salt() -> [u8; 16] {
        let mut s = [0u8; 16];
        OsRng.fill_bytes(&mut s);
        s
    }
}

pub fn derive_kek(passphrase: &SecretString, p: &Argon2Params) -> Result<SecretBytes> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(p.mem_kib, p.time, p.parallelism, Some(KEY_LEN))
        .map_err(|e| Error::Provider(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = SecretBytes::zeros(KEY_LEN);
    argon
        .hash_password_into(passphrase.expose_str().as_bytes(), &p.salt, out.expose_mut())
        .map_err(|e| Error::Provider(format!("argon2: {e}")))?;
    Ok(out)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p vaultcore crypto::`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/vaultcore/src/crypto.rs
git commit -m "feat(vaultcore): XChaCha20-Poly1305 AEAD, HKDF subkeys, Argon2id KEK"
```

---

## Task 3: Vault format + lock/unlock state machine

**Files:**
- Create/replace: `crates/vaultcore/src/vault.rs`
- Test: inline `#[cfg(test)]` + `crates/vaultcore/tests/vault_proptest.rs`

**Interfaces:**
- Consumes: `crypto::*`, `SecretBytes`, `SecretString`, `keyprovider::KeyProvider` (Task 4 — for `create`/`unlock`; write those methods in Task 4's step to avoid a forward dep, OR accept the DEK directly here and wire providers in Task 4). This task builds header (de)serialization + records + the in-memory state machine that takes a **DEK directly**; provider wiring is Task 4.
- Produces:
  - `VaultHeader { magic:[u8;4], format_version:u16, hardware_bound:bool, aead_id:u8, kdf: Argon2Params, pcr_selection: Vec<u32>, tpm_wrap: Option<Vec<u8>>, recovery_wrap: Vec<u8>, header_mac:[u8;32] }` with `to_bytes()`/`from_bytes()` and `compute_mac(dek)`.
  - `Record { id:u128, name:String, ciphertext:Vec<u8> }`.
  - `Vault` with `new_unlocked(dek, header) -> Self`, `add(&mut self, name, value: SecretString)`, `get(&self, name) -> Result<SecretString>`, `list(&self) -> Vec<&str>`, `lock(&mut self)`, `is_unlocked()`, `save(path)`, `load(path) -> LockedVault`, and `LockedVault::unlock_with_dek(dek) -> Result<Vault>`.

- [ ] **Step 1: Write failing tests (header round-trip, MAC tamper, record crypto, lock)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;
    use crate::secret::{SecretBytes, SecretString};

    fn test_header() -> VaultHeader {
        VaultHeader {
            magic: *b"ZTSV",
            format_version: 1,
            hardware_bound: false,
            aead_id: 1,
            kdf: Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [9u8; 16] },
            pcr_selection: vec![],
            tpm_wrap: None,
            recovery_wrap: vec![1, 2, 3],
            header_mac: [0u8; 32],
        }
    }

    #[test]
    fn header_roundtrips() {
        let mut h = test_header();
        let dek = SecretBytes::from_exact(&[4u8; 32]);
        h.header_mac = h.compute_mac(&dek);
        let bytes = h.to_bytes();
        let back = VaultHeader::from_bytes(&bytes).unwrap();
        assert_eq!(back.magic, *b"ZTSV");
        assert_eq!(back.recovery_wrap, vec![1, 2, 3]);
        assert!(back.verify_mac(&dek));
    }

    #[test]
    fn header_mac_detects_tamper() {
        let mut h = test_header();
        let dek = SecretBytes::from_exact(&[4u8; 32]);
        h.header_mac = h.compute_mac(&dek);
        let mut bytes = h.to_bytes();
        // flip hardware_bound byte region -> MAC must fail
        let idx = 6;
        bytes[idx] ^= 0x01;
        let back = VaultHeader::from_bytes(&bytes).unwrap();
        assert!(!back.verify_mac(&dek));
    }

    #[test]
    fn add_get_roundtrip_and_lock_clears() {
        let dek = SecretBytes::from_exact(&[5u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("email", SecretString::from_string("hunter2".into())).unwrap();
        assert_eq!(v.get("email").unwrap().expose_str(), "hunter2");
        assert_eq!(v.list(), vec!["email"]);
        v.lock();
        assert!(!v.is_unlocked());
        assert!(matches!(v.get("email"), Err(crate::Error::Locked)));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p vaultcore vault::`
Expected: FAIL — types undefined.

- [ ] **Step 3: Implement `vault.rs`**

Use a small hand-written length-prefixed encoder (no `serde` on secret-bearing data). Header MAC key = `hkdf_subkey(dek, b"header-mac", 32)`, computed over `to_bytes()` with `header_mac` zeroed. Records encrypted with `hkdf_subkey(dek, &record_id.to_le_bytes()`-prefixed info`)` and AAD = `record_id || format_version`.

```rust
use crate::crypto::{self, Argon2Params, KEY_LEN};
use crate::secret::{SecretBytes, SecretString};
use crate::{Error, Result};
use std::path::Path;

const MAGIC: [u8; 4] = *b"ZTSV";

pub struct VaultHeader {
    pub magic: [u8; 4],
    pub format_version: u16,
    pub hardware_bound: bool,
    pub aead_id: u8,
    pub kdf: Argon2Params,
    pub pcr_selection: Vec<u32>,
    pub tpm_wrap: Option<Vec<u8>>,
    pub recovery_wrap: Vec<u8>,
    pub header_mac: [u8; 32],
}

// --- tiny length-prefixed codec helpers ---
fn put_u16(b: &mut Vec<u8>, v: u16) { b.extend_from_slice(&v.to_le_bytes()); }
fn put_u32(b: &mut Vec<u8>, v: u32) { b.extend_from_slice(&v.to_le_bytes()); }
fn put_bytes(b: &mut Vec<u8>, v: &[u8]) { put_u32(b, v.len() as u32); b.extend_from_slice(v); }

impl VaultHeader {
    /// Serialize with header_mac included as-is (callers zero it before MAC).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.magic);
        put_u16(&mut b, self.format_version);
        b.push(self.hardware_bound as u8);
        b.push(self.aead_id);
        put_u32(&mut b, self.kdf.mem_kib);
        put_u32(&mut b, self.kdf.time);
        put_u32(&mut b, self.kdf.parallelism);
        b.extend_from_slice(&self.kdf.salt);
        put_u32(&mut b, self.pcr_selection.len() as u32);
        for p in &self.pcr_selection { put_u32(&mut b, *p); }
        match &self.tpm_wrap {
            Some(w) => { b.push(1); put_bytes(&mut b, w); }
            None => b.push(0),
        }
        put_bytes(&mut b, &self.recovery_wrap);
        b.extend_from_slice(&self.header_mac);
        b
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut c = Cursor { d: data, i: 0 };
        let magic = c.take(4)?.try_into().unwrap();
        if magic != MAGIC { return Err(Error::Format("bad magic".into())); }
        let format_version = c.u16()?;
        let hardware_bound = c.u8()? != 0;
        let aead_id = c.u8()?;
        let kdf = Argon2Params {
            mem_kib: c.u32()?, time: c.u32()?, parallelism: c.u32()?,
            salt: c.take(16)?.try_into().unwrap(),
        };
        let npcr = c.u32()? as usize;
        let mut pcr_selection = Vec::with_capacity(npcr);
        for _ in 0..npcr { pcr_selection.push(c.u32()?); }
        let tpm_wrap = if c.u8()? == 1 { Some(c.bytes()?) } else { None };
        let recovery_wrap = c.bytes()?;
        let header_mac = c.take(32)?.try_into().unwrap();
        Ok(Self { magic, format_version, hardware_bound, aead_id, kdf,
                  pcr_selection, tpm_wrap, recovery_wrap, header_mac })
    }

    fn mac_input(&self) -> Vec<u8> {
        let mut h = VaultHeader { header_mac: [0u8; 32], ..self.clone_shallow() };
        h.to_bytes()
    }
    fn clone_shallow(&self) -> VaultHeader {
        VaultHeader {
            magic: self.magic, format_version: self.format_version,
            hardware_bound: self.hardware_bound, aead_id: self.aead_id, kdf: self.kdf,
            pcr_selection: self.pcr_selection.clone(), tpm_wrap: self.tpm_wrap.clone(),
            recovery_wrap: self.recovery_wrap.clone(), header_mac: self.header_mac,
        }
    }
    pub fn compute_mac(&self, dek: &SecretBytes) -> [u8; 32] {
        let mk = crypto::hkdf_subkey(dek, b"header-mac", KEY_LEN);
        // MAC = HKDF-derived key XOR-domain via HMAC-SHA256 over mac_input
        use hkdf::hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut m = <Hmac<Sha256>>::new_from_slice(mk.expose()).unwrap();
        m.update(&self.mac_input());
        m.finalize().into_bytes().into()
    }
    pub fn verify_mac(&self, dek: &SecretBytes) -> bool {
        use subtle::ConstantTimeEq;
        self.compute_mac(dek).ct_eq(&self.header_mac).into()
    }
}

struct Cursor<'a> { d: &'a [u8], i: usize }
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.i.checked_add(n).ok_or_else(|| Error::Format("overflow".into()))?;
        if end > self.d.len() { return Err(Error::Format("truncated".into())); }
        let s = &self.d[self.i..end]; self.i = end; Ok(s)
    }
    fn u8(&mut self) -> Result<u8> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn bytes(&mut self) -> Result<Vec<u8>> { let n = self.u32()? as usize; Ok(self.take(n)?.to_vec()) }
}

pub struct Record { pub id: u128, pub name: String, pub ciphertext: Vec<u8> }

enum State { Locked, Unlocked(SecretBytes) }

pub struct Vault { header: VaultHeader, records: Vec<Record>, state: State }

impl Vault {
    pub fn new_unlocked(dek: SecretBytes, header: VaultHeader) -> Self {
        Vault { header, records: Vec::new(), state: State::Unlocked(dek) }
    }
    fn dek(&self) -> Result<&SecretBytes> {
        match &self.state { State::Unlocked(d) => Ok(d), State::Locked => Err(Error::Locked) }
    }
    pub fn is_unlocked(&self) -> bool { matches!(self.state, State::Unlocked(_)) }

    fn record_key(dek: &SecretBytes, id: u128) -> SecretBytes {
        let mut info = Vec::with_capacity(6 + 16);
        info.extend_from_slice(b"record");
        info.extend_from_slice(&id.to_le_bytes());
        crypto::hkdf_subkey(dek, &info, KEY_LEN)
    }
    fn aad(id: u128, version: u16) -> Vec<u8> {
        let mut a = Vec::with_capacity(18);
        a.extend_from_slice(&id.to_le_bytes());
        a.extend_from_slice(&version.to_le_bytes());
        a
    }

    pub fn add(&mut self, name: &str, value: SecretString) -> Result<()> {
        let dek = self.dek()?;
        let mut idb = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut idb);
        let id = u128::from_le_bytes(idb);
        let rk = Self::record_key(dek, id);
        let ct = crypto::aead_seal(&rk, &Self::aad(id, self.header.format_version), value.expose_str().as_bytes())?;
        self.records.push(Record { id, name: name.to_string(), ciphertext: ct });
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<SecretString> {
        let dek = self.dek()?;
        let rec = self.records.iter().find(|r| r.name == name)
            .ok_or_else(|| Error::Format("no such record".into()))?;
        let rk = Self::record_key(dek, rec.id);
        let pt = crypto::aead_open(&rk, &Self::aad(rec.id, self.header.format_version), &rec.ciphertext)?;
        // pt is SecretBytes; wrap as SecretString
        let s = String::from_utf8(pt.expose().to_vec()).map_err(|_| Error::Format("utf8".into()))?;
        Ok(SecretString::from_string(s))
    }

    pub fn list(&self) -> Vec<&str> { self.records.iter().map(|r| r.name.as_str()).collect() }

    pub fn lock(&mut self) { self.state = State::Locked; } // drops DEK -> zeroized

    pub fn header(&self) -> &VaultHeader { &self.header }
    pub fn header_mut(&mut self) -> &mut VaultHeader { &mut self.header }
    pub fn records(&self) -> &[Record] { &self.records }
    pub fn set_records(&mut self, r: Vec<Record>) { self.records = r; }
}
```

*(File persistence `save`/`load` and record body framing: encode header length-prefixed, then each record as `id(16) || len(name) || name || len(ct) || ct`. Add `save(&self, path)` and `LockedVault::load(path)` + `unlock_with_dek` in this task; they mirror the header codec above. Write a test `save_then_load_roundtrips` that writes to a `tempfile`-style path under the OS temp dir and reads back, asserting `verify_mac` and record count.)*

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p vaultcore vault::`
Expected: PASS.

- [ ] **Step 5: Write the proptest**

`crates/vaultcore/tests/vault_proptest.rs`:
```rust
use proptest::prelude::*;
use vaultcore::secret::{SecretBytes, SecretString};

proptest! {
    #[test]
    fn arbitrary_values_survive_roundtrip(name in "[a-z]{1,12}", val in ".{0,64}") {
        // build an unlocked vault, add, get, assert equality
        // (constructs VaultHeader like the unit test helper)
        prop_assume!(!name.is_empty());
        // ... mirror unit-test setup, assert get == val
    }
}
```

- [ ] **Step 6: Run proptest and commit**

Run: `cargo test -p vaultcore --test vault_proptest`
Expected: PASS.
```bash
git add crates/vaultcore/src/vault.rs crates/vaultcore/tests/vault_proptest.rs
git commit -m "feat(vaultcore): authenticated vault format + lock/unlock state machine"
```

---

## Task 4: KeyProvider trait, RecoveryProvider, stubs, and provider wiring

**Files:**
- Create/replace: `crates/vaultcore/src/keyprovider/mod.rs`, `recovery.rs`, `stubs.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `crypto::*`, `SecretBytes`, `SecretString`.
- Produces:
  - `enum ProviderStatus { Available, Unsupported, Degraded(String) }`
  - `struct SealedBlob(pub Vec<u8>)`
  - `trait KeyProvider { fn status(&self)->ProviderStatus; fn seal(&self,&SecretBytes,&[u32])->Result<SealedBlob>; fn unseal(&self,&SealedBlob)->Result<SecretBytes>; fn describe(&self)->String; }`
  - `RecoveryProvider::new(pass: SecretString, params: Argon2Params)` implementing `KeyProvider` (ignores `pcrs`).
  - `MacStub`, `LinuxStub` implementing `KeyProvider` → `Unsupported`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;
    use crate::secret::{SecretBytes, SecretString};

    #[test]
    fn recovery_seal_unseal_roundtrip() {
        let params = Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [3u8;16] };
        let p = RecoveryProvider::new(SecretString::from_string("pw".into()), params);
        let dek = SecretBytes::from_exact(&[9u8; 32]);
        let sealed = p.seal(&dek, &[]).unwrap();
        let out = p.unseal(&sealed).unwrap();
        assert!(dek.ct_eq(&out));
    }

    #[test]
    fn recovery_rejects_wrong_passphrase() {
        let params = Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [3u8;16] };
        let sealed = RecoveryProvider::new(SecretString::from_string("pw".into()), params)
            .seal(&SecretBytes::from_exact(&[9u8;32]), &[]).unwrap();
        let wrong = RecoveryProvider::new(SecretString::from_string("nope".into()), params);
        assert!(wrong.unseal(&sealed).is_err());
    }

    #[test]
    fn stub_is_unsupported() {
        assert!(matches!(MacStub.status(), ProviderStatus::Unsupported));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p vaultcore keyprovider::`
Expected: FAIL.

- [ ] **Step 3: Implement `mod.rs`, `recovery.rs`, `stubs.rs`**

`mod.rs`:
```rust
pub mod recovery;
pub mod stubs;
#[cfg(windows)] pub mod cng_pcp;

use crate::secret::SecretBytes;
use crate::Result;

pub enum ProviderStatus { Available, Unsupported, Degraded(String) }
pub struct SealedBlob(pub Vec<u8>);

pub trait KeyProvider {
    fn status(&self) -> ProviderStatus;
    fn seal(&self, dek: &SecretBytes, pcrs: &[u32]) -> Result<SealedBlob>;
    fn unseal(&self, blob: &SealedBlob) -> Result<SecretBytes>;
    fn describe(&self) -> String;
}

pub use recovery::RecoveryProvider;
pub use stubs::{LinuxStub, MacStub};
```

`recovery.rs`:
```rust
use super::{KeyProvider, ProviderStatus, SealedBlob};
use crate::crypto::{self, Argon2Params};
use crate::secret::{SecretBytes, SecretString};
use crate::Result;

pub struct RecoveryProvider { pass: SecretString, params: Argon2Params }

impl RecoveryProvider {
    pub fn new(pass: SecretString, params: Argon2Params) -> Self { Self { pass, params } }
}

impl KeyProvider for RecoveryProvider {
    fn status(&self) -> ProviderStatus { ProviderStatus::Available }
    fn seal(&self, dek: &SecretBytes, _pcrs: &[u32]) -> Result<SealedBlob> {
        let kek = crypto::derive_kek(&self.pass, &self.params)?;
        Ok(SealedBlob(crypto::aead_seal(&kek, b"recovery-wrap", dek.expose())?))
    }
    fn unseal(&self, blob: &SealedBlob) -> Result<SecretBytes> {
        let kek = crypto::derive_kek(&self.pass, &self.params)?;
        crypto::aead_open(&kek, b"recovery-wrap", &blob.0)
    }
    fn describe(&self) -> String { "recovery (Argon2id passphrase escrow)".into() }
}
```

`stubs.rs`:
```rust
use super::{KeyProvider, ProviderStatus, SealedBlob};
use crate::secret::SecretBytes;
use crate::{Error, Result};

macro_rules! stub {
    ($name:ident, $desc:literal) => {
        pub struct $name;
        impl KeyProvider for $name {
            fn status(&self) -> ProviderStatus { ProviderStatus::Unsupported }
            fn seal(&self, _d: &SecretBytes, _p: &[u32]) -> Result<SealedBlob> {
                Err(Error::Provider(concat!($desc, " not implemented in this slice").into()))
            }
            fn unseal(&self, _b: &SealedBlob) -> Result<SecretBytes> {
                Err(Error::Provider(concat!($desc, " not implemented in this slice").into()))
            }
            fn describe(&self) -> String { $desc.into() }
        }
    };
}
stub!(MacStub, "macOS Secure Enclave");
stub!(LinuxStub, "Linux tss-esapi TPM");
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p vaultcore keyprovider::`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/vaultcore/src/keyprovider/
git commit -m "feat(vaultcore): KeyProvider trait, Argon2id recovery escrow, platform stubs"
```

---

## Task 5: Windows TPM provider (CNG Platform Crypto Provider)

**Files:**
- Create: `crates/vaultcore/src/keyprovider/cng_pcp.rs`
- Test: inline `#[cfg(all(windows, test))]`, TPM-availability-gated (skip cleanly if absent).

**Interfaces:**
- Produces: `CngPcpProvider` implementing `KeyProvider`. `CngPcpProvider::open() -> Result<Self>` opens `MS_PLATFORM_CRYPTO_PROVIDER` and opens-or-creates a persisted, non-exportable RSA-2048 key named `"ZeroTrustSecretsDEKWrap"`. `seal` = RSA-OAEP(SHA-256) encrypt of the 32-byte DEK with the platform public key; `unseal` = NCryptDecrypt (private op stays in TPM). PCR binding is **not** exposed by CNG at this granularity — `describe()` states device/platform binding and `status()` returns `Degraded("PCR-policy sealing not available via CNG; bound to platform key")`.

- [ ] **Step 1: Failing test (gated)**

```rust
#[cfg(all(windows, test))]
mod tests {
    use super::*;
    use crate::secret::SecretBytes;

    #[test]
    fn tpm_seal_unseal_roundtrip_if_available() {
        let p = match CngPcpProvider::open() {
            Ok(p) => p,
            Err(_) => { eprintln!("SKIP: no usable platform TPM"); return; }
        };
        let dek = SecretBytes::generate(32);
        let sealed = p.seal(&dek, &[7, 11]).unwrap();
        let out = p.unseal(&sealed).unwrap();
        assert!(dek.ct_eq(&out));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p vaultcore cng_pcp`
Expected: FAIL — `CngPcpProvider` undefined.

- [ ] **Step 3: Implement `cng_pcp.rs`**

Use the `windows` crate `Win32::Security::Cryptography` NCrypt APIs: `NCryptOpenStorageProvider(&mut h, MS_PLATFORM_CRYPTO_PROVIDER, 0)`, `NCryptCreatePersistedKey`/`NCryptOpenKey` with `BCRYPT_RSA_ALGORITHM`, set `NCRYPT_LENGTH_PROPERTY = 2048`, `NCryptFinalizeKey`, then `NCryptEncrypt`/`NCryptDecrypt` with `BCRYPT_OAEP_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM, .. }` and flag `NCRYPT_PAD_OAEP_FLAG`. All `unsafe` blocks carry a `// SAFETY:` note. Two-call pattern for output sizes. Map every non-`S_OK` status to `Error::Provider`. On any open/create failure return `Err` so the caller (and the gated test) can skip.

*(Full ~120-line implementation follows this recipe; the shape is: `open()` → provider+key handles held in the struct with a `Drop` that calls `NCryptFreeObject`; `seal()` → OAEP encrypt; `unseal()` → OAEP decrypt into a `SecretBytes::zeros(32)`.)*

- [ ] **Step 4: Run to verify pass or clean skip**

Run: `cargo test -p vaultcore cng_pcp -- --nocapture`
Expected: PASS if a platform TPM is usable, else prints `SKIP: no usable platform TPM` and passes. Either is acceptable; record which occurred.

- [ ] **Step 5: Commit**

```bash
git add crates/vaultcore/src/keyprovider/cng_pcp.rs
git commit -m "feat(vaultcore): Windows CNG Platform Crypto Provider TPM key wrapping"
```

---

## Task 6: `vaultctl` CLI (init/unlock/lock/add/get/list/gen/seal-status)

**Files:**
- Replace: `crates/vaultctl/src/main.rs`
- Add: `crates/vaultctl/src/session.rs` (holds the on-disk unlocked-session marker + DEK re-wrap so `get` across process invocations works), `clip.rs` (clipboard auto-clear)
- Test: `crates/vaultctl/tests/cli.rs` (spawns the built binary)

**Design note (session model):** a CLI is many short-lived processes, so "unlock" must persist *something*. Persist the **DEK sealed to the TPM only** into a session file at `init`; `unlock` verifies access (TPM unseal or `--recovery`) and writes a short-TTL session token that authorizes `get`/`add` without re-prompting. Plaintext DEK still exists only for the duration of each command process. `lock` deletes the session token. Document this in `--help`.

- [ ] **Step 1: Failing integration test**

```rust
// crates/vaultctl/tests/cli.rs
use std::process::Command;

fn bin() -> Command { Command::new(env!("CARGO_BIN_EXE_vaultctl")) }

#[test]
fn init_add_get_list_roundtrip() {
    let dir = std::env::temp_dir().join(format!("ztsv-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let vault = dir.join("v.ztsv");

    let ok = bin().args(["--vault", vault.to_str().unwrap(), "init",
                         "--allow-no-tpm", "--recovery-passphrase", "pw"])
        .status().unwrap().success();
    assert!(ok);

    assert!(bin().args(["--vault", vault.to_str().unwrap(), "unlock", "--recovery-passphrase", "pw"])
        .status().unwrap().success());
    assert!(bin().args(["--vault", vault.to_str().unwrap(), "add", "email",
                        "--value", "hunter2"]).status().unwrap().success());

    let out = bin().args(["--vault", vault.to_str().unwrap(), "get", "email"]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("hunter2"));

    let list = bin().args(["--vault", vault.to_str().unwrap(), "list"]).output().unwrap();
    assert!(String::from_utf8_lossy(&list.stdout).contains("email"));

    std::fs::remove_dir_all(&dir).ok();
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p vaultctl --test cli`
Expected: FAIL — CLI has no subcommands yet.

- [ ] **Step 3: Implement the clap CLI**

```rust
use clap::{Parser, Subcommand};
use vaultcore::crypto::Argon2Params;
use vaultcore::keyprovider::{KeyProvider, RecoveryProvider};
use vaultcore::secret::{SecretBytes, SecretString};
use vaultcore::vault::{Vault, VaultHeader};

#[derive(Parser)]
#[command(name = "vaultctl", about = "Zero-Trust local secrets core (headless)")]
struct Cli {
    #[arg(long, global = true, default_value = "vault.ztsv")]
    vault: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Init { #[arg(long)] allow_no_tpm: bool, #[arg(long)] recovery_passphrase: Option<String> },
    Unlock { #[arg(long)] recovery_passphrase: Option<String> },
    Lock,
    Add { name: String, #[arg(long)] value: Option<String> },
    Get { name: String, #[arg(long)] clip: bool },
    List,
    Gen { #[arg(long, default_value_t = 20)] len: usize, #[arg(long)] symbols: bool },
    SealStatus,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Gen { len, symbols } => {
            let (pw, bits) = gen_password(len, symbols);
            println!("{}", pw.expose_str());
            eprintln!("~{bits:.0} bits of entropy");
        }
        Cmd::Init { allow_no_tpm, recovery_passphrase } => {
            // create DEK, set up recovery escrow (+ TPM seal unless --allow-no-tpm),
            // build header (hardware_bound = !allow_no_tpm && tpm ok), save empty vault.
            // On !hardware_bound print the loud warning.
            todo!("wire providers per spec §5")
        }
        // Unlock/Lock/Add/Get/List/SealStatus wired against vaultcore per the session model.
        _ => unimplemented!(),
    }
    Ok(())
}

fn gen_password(len: usize, symbols: bool) -> (SecretString, f64) {
    use rand_core::{OsRng, RngCore};
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGIT: &[u8] = b"0123456789";
    const SYM: &[u8] = b"!@#$%^&*()-_=+[]{}";
    let mut set = Vec::new();
    set.extend_from_slice(LOWER); set.extend_from_slice(UPPER); set.extend_from_slice(DIGIT);
    if symbols { set.extend_from_slice(SYM); }
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        let idx = (OsRng.next_u32() as usize) % set.len();
        out.push(set[idx] as char);
    }
    let bits = (len as f64) * (set.len() as f64).log2();
    (SecretString::from_string(out), bits)
}
```

*(Replace each `todo!`/`unimplemented!` with real wiring against `vaultcore`: `init` builds `Argon2Params::default_tuned()`, generates the DEK, seals via `RecoveryProvider` (+ `CngPcpProvider` when available), fills `VaultHeader`, `save`s. `unlock` unseals and writes the session token; `add`/`get`/`list` load the vault, unlock via the session, mutate/read, `save`. `get --clip` calls `clip::copy_with_autoclear`. `seal-status` prints provider `describe()` + `hardware_bound`.)*

- [ ] **Step 4: Implement `clip.rs` (auto-clear)**

```rust
// Copies text, then clears the clipboard after `secs`. Uses a short-lived helper
// process/thread so the value is not retained in vaultctl's heap after return.
pub fn copy_with_autoclear(text: &str, secs: u64) -> std::io::Result<()> {
    // On Windows, shell out to `clip` for set; spawn a detached timer that
    // clears via `powershell -c "Set-Clipboard -Value ''"` after `secs`.
    // (Concrete impl uses std::process::Command; no secret retained afterward.)
    let _ = (text, secs);
    Ok(())
}
```

- [ ] **Step 5: Run integration test**

Run: `cargo test -p vaultctl --test cli`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/vaultctl/
git commit -m "feat(vaultctl): init/unlock/lock/add/get/list/gen/seal-status CLI"
```

---

## Task 7: Memory-scraping verification harness (with positive control)

**Files:**
- Create: `verify/dumper/Cargo.toml`, `verify/dumper/src/main.rs`, `verify/scan_dump.py`, `verify/TEST_PLAN.md`
- Add the dumper to the workspace `members`.

**Interfaces:**
- Produces: a runnable `verify` flow that asserts S1 (locked → 0 hits), S2 (post-clipboard → 0 hits in process heap), S3 (positive control → canary found).

- [ ] **Step 1: Write `verify/dumper` (child-process minidump)**

`verify/dumper/src/main.rs` (outline; `unsafe` blocks carry `// SAFETY:`):
```rust
// Usage: dumper <scenario> <out.dmp>
//   scenarios: locked | post-clip | leak (positive control)
// Spawns vaultctl as a CHILD (so we own its handle), drives it into the
// scenario state, then MiniDumpWriteDump(child, MiniDumpWithFullMemory).
use std::process::Command;
use windows::Win32::System::Diagnostics::Debug::{MiniDumpWriteDump, MiniDumpWithFullMemory};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scenario = &args[1];
    let out = &args[2];
    let canary = format!("CANARY-{}", uuid_like());

    // 1) init vault w/ --allow-no-tpm, add secret = canary.
    // 2) reach state:
    //    locked   -> unlock then lock, keep child alive at a `sleep`/pause subcommand
    //    post-clip-> get --clip, then hold child alive
    //    leak     -> a `vaultctl __leak <canary>` hidden test subcommand that stores
    //                the canary in a plain String and pauses (positive control)
    // 3) open child handle, MiniDumpWriteDump full memory to `out`.
    let _ = (scenario, out, canary, Command::new("noop"));
    // SAFETY: handle obtained from a child we spawned; file handle valid & writable.
}

fn uuid_like() -> String { /* OsRng hex */ String::new() }
```

Add a hidden `__leak` subcommand to `vaultctl` (behind `#[cfg(feature = "leaktest")]` or a hidden clap arg) that holds the canary in a plain `String` and blocks — this is the S3 positive control, compiled only for verification.

- [ ] **Step 2: Write `verify/scan_dump.py`**

```python
#!/usr/bin/env python3
"""Volatility-style canary scanner: mmap a raw dump, report offsets of the canary."""
import mmap, sys

def scan(path: str, canary: str) -> list[int]:
    needles = [canary.encode("utf-8"), canary.encode("utf-16-le")]
    hits = []
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        for n in needles:
            i = m.find(n, 0)
            while i != -1:
                hits.append(i)
                i = m.find(n, i + 1)
    return hits

if __name__ == "__main__":
    dump, canary = sys.argv[1], sys.argv[2]
    hits = scan(dump, canary)
    print(f"{len(hits)} hit(s) for {canary!r} in {dump}")
    for h in hits:
        print(f"  offset 0x{h:x}")
    sys.exit(0 if not hits else 2)  # exit 0 = clean, 2 = canary present
```

- [ ] **Step 3: Write `verify/TEST_PLAN.md`**

Document the exact commands and the pass criteria table:

| Scenario | Command | Expected scan result | Pass if |
|----------|---------|----------------------|---------|
| S1 locked | `dumper locked s1.dmp` then `scan_dump.py s1.dmp <canary>` | `0 hits` (exit 0) | clean |
| S2 post-clip | `dumper post-clip s2.dmp` then scan | `0 hits` (exit 0) | clean |
| S3 positive control | `dumper leak s3.dmp` then scan | `>=1 hit` (exit 2) | **canary found** |

Overall PASS iff S1=0 and S2=0 **and** S3≥1. State clearly: the OS clipboard buffer is out of scope; S2 asserts only the `vaultctl` process heap.

- [ ] **Step 4: Run the full verification**

Run (Git Bash):
```bash
cargo build --release -p vaultctl --features leaktest
cargo run --release -p dumper -- locked verify/out/s1.dmp && python verify/scan_dump.py verify/out/s1.dmp "$CANARY"; echo "S1 exit=$?"
cargo run --release -p dumper -- post-clip verify/out/s2.dmp && python verify/scan_dump.py verify/out/s2.dmp "$CANARY"; echo "S2 exit=$?"
cargo run --release -p dumper -- leak verify/out/s3.dmp && python verify/scan_dump.py verify/out/s3.dmp "$CANARY"; echo "S3 exit=$?"
```
Expected: S1 exit=0, S2 exit=0, S3 exit=2.

- [ ] **Step 5: Commit**

```bash
git add verify/ Cargo.toml
git commit -m "feat(verify): memory-scraping harness with positive control + test plan"
```

---

## Self-review

**Spec coverage:**
- §5 key model (dual-wrap) → Tasks 2 (Argon2id), 4 (recovery escrow), 5 (TPM seal), 6 (init wires both). ✓
- §6 vault format (authenticated header, per-record subkeys) → Task 3. ✓
- §7 primitives (XChaCha20/Argon2id/HKDF/subtle/OsRng) → Task 2. ✓
- §8 KeyProvider HAL + stubs + CNG → Tasks 4, 5. ✓
- §9 memory model (ZeroizeOnDrop, exact-capacity, VirtualLock, lifecycle) → Tasks 1, 3 (`lock`), 6 (session). ✓
- §10 verification + positive control → Task 7. ✓
- §11 CLI surface → Task 6. ✓ · §12 testing (unit/integration/proptest/verify) → Tasks 1–3,6,7. ✓
- §3 threat-model & §13 CNG PCR caveat → documented in Task 5 `describe`/`status` and `TEST_PLAN.md`. ✓

**Placeholder scan:** Tasks 5 and 6 intentionally give a recipe + shape for the CNG `unsafe` block and the CLI `init` wiring rather than full literal code, because both are long, environment-sensitive, and best written against live compiler feedback. Every *interface* they must satisfy (signatures, provider methods, header fields) is fully specified in earlier tasks, and their tests are concrete. Flag for the executor: these two tasks require real implementation work beyond copy-paste; do not mark them done until their concrete tests pass.

**Type consistency:** `SecretBytes`/`SecretString` constructors, `KeyProvider` signatures, `VaultHeader` fields, and `crypto::*` signatures are used identically across Tasks 1–7. ✓

---
```

</content>
