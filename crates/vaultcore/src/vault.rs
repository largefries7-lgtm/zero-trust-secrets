//! On-disk vault format and lock/unlock state machine.
//!
//! Layout: a versioned, authenticated header (HMAC-SHA256 over the header
//! bytes, keyed by an HKDF subkey of the DEK) followed by a sequence of
//! records, each individually encrypted with XChaCha20-Poly1305 under a
//! per-record HKDF subkey. Tamper anywhere in the header or a record must
//! fail closed (`Error::AuthFailed`), never silently return partial or
//! wrong data.

use crate::crypto::{self, Argon2Params, KEY_LEN};
use crate::secret::{SecretBytes, SecretString};
use crate::{Error, Result};
use std::path::Path;

const MAGIC: [u8; 4] = *b"ZTSV";
/// Current on-disk format version. v2 = two-factor envelope (see `envelope.rs`).
/// v1 (single-factor: TPM-wraps-DEK *or* passphrase-wraps-DEK) is no longer read
/// by the hot path; `vaultctl migrate` upgrades a v1 file to v2.
pub const FORMAT_VERSION: u16 = 2;

/// Authenticated vault header (format v2).
///
/// The DEK is wrapped by `dek_wrap` under a two-factor KEK (see `envelope.rs`):
/// `tpm_wrap` seals the random TPM secret factor (present iff `hardware_bound`),
/// and `kdf` parameterizes the Argon2id passphrase factor. `recovery_wrap` /
/// `recovery_kdf` are an OPTIONAL single-factor escrow.
#[derive(Clone)]
pub struct VaultHeader {
    pub magic: [u8; 4],
    pub format_version: u16,
    pub hardware_bound: bool,
    pub aead_id: u8,
    /// Argon2id parameters/salt for the unlock passphrase factor.
    pub kdf: Argon2Params,
    pub pcr_selection: Vec<u32>,
    /// RSA-OAEP-sealed 32-byte TPM secret factor. `Some` iff `hardware_bound`.
    pub tpm_wrap: Option<Vec<u8>>,
    /// Primary wrap: `AEAD(KEK, DEK)` where `KEK = HKDF([tpm_secret ‖] pass_key)`.
    pub dek_wrap: Vec<u8>,
    /// Optional single-factor recovery escrow: `AEAD(Argon2id(recovery_pass), DEK)`.
    pub recovery_wrap: Option<Vec<u8>>,
    /// Argon2id parameters/salt for the recovery passphrase. `Some` iff `recovery_wrap`.
    pub recovery_kdf: Option<Argon2Params>,
    pub header_mac: [u8; 32],
}

// --- tiny length-prefixed codec helpers ---
fn put_u16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put_bytes(b: &mut Vec<u8>, v: &[u8]) {
    put_u32(b, v.len() as u32);
    b.extend_from_slice(v);
}
fn put_argon2(b: &mut Vec<u8>, p: &Argon2Params) {
    put_u32(b, p.mem_kib);
    put_u32(b, p.time);
    put_u32(b, p.parallelism);
    b.extend_from_slice(&p.salt);
}

impl VaultHeader {
    /// Serialize the v2 header. `header_mac` is written as-is (callers zero it
    /// before computing the MAC over these bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.magic);
        put_u16(&mut b, self.format_version);
        b.push(self.hardware_bound as u8);
        b.push(self.aead_id);
        put_argon2(&mut b, &self.kdf);
        put_u32(&mut b, self.pcr_selection.len() as u32);
        for p in &self.pcr_selection {
            put_u32(&mut b, *p);
        }
        match &self.tpm_wrap {
            Some(w) => {
                b.push(1);
                put_bytes(&mut b, w);
            }
            None => b.push(0),
        }
        put_bytes(&mut b, &self.dek_wrap);
        match (&self.recovery_wrap, &self.recovery_kdf) {
            (Some(rw), Some(rk)) => {
                b.push(1);
                put_argon2(&mut b, rk);
                put_bytes(&mut b, rw);
            }
            _ => b.push(0),
        }
        b.extend_from_slice(&self.header_mac);
        b
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut c = Cursor { d: data, i: 0 };
        let magic: [u8; 4] = c
            .take(4)?
            .try_into()
            .map_err(|_| Error::Format("magic".into()))?;
        if magic != MAGIC {
            return Err(Error::Format("bad magic".into()));
        }
        let format_version = c.u16()?;
        if format_version != FORMAT_VERSION {
            // v1 files are single-factor; they are not read by the hot path.
            return Err(Error::Format(format!(
                "unsupported vault format version {format_version} (expected {FORMAT_VERSION}); \
                 if this is a v1 vault, run `vaultctl migrate`"
            )));
        }
        let hardware_bound = c.u8()? != 0;
        let aead_id = c.u8()?;
        let kdf = c.argon2()?;
        let npcr = c.u32()? as usize;
        // Do NOT pre-allocate from the untrusted `npcr`: like the record count,
        // a tiny file claiming a huge PCR count would otherwise force a large
        // up-front allocation before parsing fails. Grow as entries parse; each
        // `c.u32()` is bounds-checked, so work is bounded by the real file size.
        let mut pcr_selection = Vec::new();
        for _ in 0..npcr {
            pcr_selection.push(c.u32()?);
        }
        let tpm_wrap = if c.u8()? == 1 { Some(c.bytes()?) } else { None };
        let dek_wrap = c.bytes()?;
        let (recovery_wrap, recovery_kdf) = if c.u8()? == 1 {
            let rk = c.argon2()?;
            let rw = c.bytes()?;
            (Some(rw), Some(rk))
        } else {
            (None, None)
        };
        let header_mac: [u8; 32] = c
            .take(32)?
            .try_into()
            .map_err(|_| Error::Format("header_mac".into()))?;
        Ok(Self {
            magic,
            format_version,
            hardware_bound,
            aead_id,
            kdf,
            pcr_selection,
            tpm_wrap,
            dek_wrap,
            recovery_wrap,
            recovery_kdf,
            header_mac,
        })
    }

    fn mac_input(&self) -> Vec<u8> {
        let mut h = self.clone();
        h.header_mac = [0u8; 32];
        h.to_bytes()
    }

    pub fn compute_mac(&self, dek: &SecretBytes, records: &[Record]) -> [u8; 32] {
        let mk = crypto::hkdf_subkey(dek, b"header-mac", KEY_LEN);
        use hkdf::hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut m = <Hmac<Sha256>>::new_from_slice(mk.expose()).expect("hmac accepts any key len");
        m.update(&self.mac_input());
        // authenticate the record set: count, then each record in order
        m.update(&(records.len() as u32).to_le_bytes());
        for r in records {
            m.update(&r.id.to_le_bytes());
            m.update(&(r.name.len() as u32).to_le_bytes());
            m.update(r.name.as_bytes());
            m.update(&(r.ciphertext.len() as u32).to_le_bytes());
            m.update(&r.ciphertext);
        }
        m.finalize().into_bytes().into()
    }

    pub fn verify_mac(&self, dek: &SecretBytes, records: &[Record]) -> bool {
        use subtle::ConstantTimeEq;
        self.compute_mac(dek, records).ct_eq(&self.header_mac).into()
    }

    /// Build a fresh v2 header. `dek_wrap` is the primary two-factor wrap;
    /// `tpm_wrap` seals the TPM secret factor (`Some` iff hardware-bound); the
    /// recovery pair is the optional single-factor escrow. `header_mac` is filled
    /// by `Vault::save`. `aead_id`/`pcr_selection` take their defaults.
    pub fn new_v2(
        hardware_bound: bool,
        kdf: Argon2Params,
        tpm_wrap: Option<Vec<u8>>,
        dek_wrap: Vec<u8>,
        recovery: Option<(Vec<u8>, Argon2Params)>,
    ) -> Self {
        let (recovery_wrap, recovery_kdf) = match recovery {
            Some((rw, rk)) => (Some(rw), Some(rk)),
            None => (None, None),
        };
        VaultHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            hardware_bound,
            aead_id: 1,
            kdf,
            pcr_selection: vec![],
            tpm_wrap,
            dek_wrap,
            recovery_wrap,
            recovery_kdf,
            header_mac: [0u8; 32],
        }
    }
}

struct Cursor<'a> {
    d: &'a [u8],
    i: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .i
            .checked_add(n)
            .ok_or_else(|| Error::Format("overflow".into()))?;
        if end > self.d.len() {
            return Err(Error::Format("truncated".into()));
        }
        let s = &self.d[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn argon2(&mut self) -> Result<Argon2Params> {
        Ok(Argon2Params {
            mem_kib: self.u32()?,
            time: self.u32()?,
            parallelism: self.u32()?,
            salt: self
                .take(16)?
                .try_into()
                .map_err(|_| Error::Format("argon2 salt".into()))?,
        })
    }
}

pub struct Record {
    pub id: u128,
    pub name: String,
    pub ciphertext: Vec<u8>,
}

impl Record {
    fn to_bytes(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.id.to_le_bytes());
        put_bytes(b, self.name.as_bytes());
        put_bytes(b, &self.ciphertext);
    }

    fn from_cursor(c: &mut Cursor) -> Result<Self> {
        let id_bytes: [u8; 16] = c
            .take(16)?
            .try_into()
            .map_err(|_| Error::Format("record id".into()))?;
        let id = u128::from_le_bytes(id_bytes);
        let name_bytes = c.bytes()?;
        let name =
            String::from_utf8(name_bytes).map_err(|_| Error::Format("record name utf8".into()))?;
        let ciphertext = c.bytes()?;
        Ok(Record { id, name, ciphertext })
    }
}

enum State {
    Locked,
    Unlocked(SecretBytes),
}

/// A vault whose header and record framing are known but which has not been
/// authenticated/decrypted yet. Holds no DEK and no plaintext.
pub struct LockedVault {
    header: VaultHeader,
    records: Vec<Record>,
}

impl LockedVault {
    /// Read a vault file from disk and parse its header + record framing,
    /// without authenticating or decrypting anything.
    pub fn load(path: &Path) -> Result<LockedVault> {
        let data = std::fs::read(path)?;
        let mut c = Cursor { d: &data, i: 0 };
        let header_len = c.u32()? as usize;
        let header_bytes = c.take(header_len)?;
        let header = VaultHeader::from_bytes(header_bytes)?;

        let num_records = c.u32()? as usize;
        // Do NOT pre-allocate from the untrusted `num_records`: a tiny file
        // claiming a huge count would otherwise force a large up-front
        // allocation (memory-amplification DoS) before parsing fails. Grow as
        // records actually parse; each `from_cursor` is bounds-checked against
        // the remaining bytes, so total work is bounded by the real file size.
        let mut records = Vec::new();
        for _ in 0..num_records {
            records.push(Record::from_cursor(&mut c)?);
        }
        Ok(LockedVault { header, records })
    }

    /// Verify the header MAC against the supplied DEK and, on success,
    /// return an unlocked `Vault`. Fails closed: on MAC mismatch this
    /// returns `Error::AuthFailed` and no usable vault is produced.
    pub fn unlock_with_dek(self, dek: SecretBytes) -> Result<Vault> {
        if !self.header.verify_mac(&dek, &self.records) {
            return Err(Error::AuthFailed);
        }
        Ok(Vault {
            header: self.header,
            records: self.records,
            state: State::Unlocked(dek),
        })
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Record names as stored (authenticated plaintext metadata). Read-only;
    /// exposes no key material and does not require the DEK. Used by `list`.
    pub fn record_names(&self) -> Vec<&str> {
        self.records.iter().map(|r| r.name.as_str()).collect()
    }

    /// v2 primary unlock: derive the DEK from the unlock passphrase (+ the TPM
    /// secret factor, for a hardware-bound vault) via the two-factor envelope,
    /// then verify the header MAC. Fails closed (`Error::AuthFailed`) on a wrong
    /// passphrase, wrong/missing TPM secret, or a tampered header/record set.
    pub fn unlock_two_factor(
        self,
        passphrase: &SecretString,
        tpm_secret: Option<&SecretBytes>,
    ) -> Result<Vault> {
        let dek = crate::envelope::unwrap_dek(
            &self.header.dek_wrap,
            passphrase,
            &self.header.kdf,
            tpm_secret,
        )?;
        self.unlock_with_dek(dek)
    }

    /// v2 recovery unlock: derive the DEK from the recovery passphrase alone
    /// (single factor). Errors if this vault has no recovery escrow.
    pub fn unlock_recovery(self, recovery_pass: &SecretString) -> Result<Vault> {
        let (rw, rk) = match (
            self.header.recovery_wrap.as_ref(),
            self.header.recovery_kdf.as_ref(),
        ) {
            (Some(rw), Some(rk)) => (rw.clone(), *rk),
            _ => return Err(Error::Provider("this vault has no recovery escrow".into())),
        };
        let dek = crate::envelope::unwrap_dek_recovery(&rw, recovery_pass, &rk)?;
        self.unlock_with_dek(dek)
    }
}

pub struct Vault {
    header: VaultHeader,
    records: Vec<Record>,
    state: State,
}

impl Vault {
    pub fn new_unlocked(dek: SecretBytes, header: VaultHeader) -> Self {
        Vault { header, records: Vec::new(), state: State::Unlocked(dek) }
    }
    fn dek(&self) -> Result<&SecretBytes> {
        match &self.state {
            State::Unlocked(d) => Ok(d),
            State::Locked => Err(Error::Locked),
        }
    }
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, State::Unlocked(_))
    }

    fn record_key(dek: &SecretBytes, id: u128) -> SecretBytes {
        let mut info = Vec::with_capacity(6 + 16);
        info.extend_from_slice(b"record");
        info.extend_from_slice(&id.to_le_bytes());
        crypto::hkdf_subkey(dek, &info, KEY_LEN)
    }
    fn aad(id: u128, version: u16, name: &str) -> Vec<u8> {
        let mut a = Vec::with_capacity(18 + name.len());
        a.extend_from_slice(&id.to_le_bytes());
        a.extend_from_slice(&version.to_le_bytes());
        a.extend_from_slice(name.as_bytes());
        a
    }

    pub fn add(&mut self, name: &str, value: SecretString) -> Result<()> {
        let dek = self.dek()?;
        let mut idb = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut idb);
        let id = u128::from_le_bytes(idb);
        let rk = Self::record_key(dek, id);
        let ct = crypto::aead_seal(
            &rk,
            &Self::aad(id, self.header.format_version, name),
            value.expose_str().as_bytes(),
        )?;
        self.records.push(Record { id, name: name.to_string(), ciphertext: ct });
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<SecretString> {
        let dek = self.dek()?;
        let rec = self
            .records
            .iter()
            .find(|r| r.name == name)
            .ok_or_else(|| Error::Format("no such record".into()))?;
        let rk = Self::record_key(dek, rec.id);
        let pt = crypto::aead_open(
            &rk,
            &Self::aad(rec.id, self.header.format_version, &rec.name),
            &rec.ciphertext,
        )?;
        // Wrap the already-locked plaintext in place: no `to_vec()` copy into
        // ordinary heap, and on non-UTF-8 the buffer is zeroized on drop.
        SecretString::from_secret_bytes(pt)
            .ok_or_else(|| Error::Format("record value is not valid utf8".into()))
    }

    pub fn list(&self) -> Vec<&str> {
        self.records.iter().map(|r| r.name.as_str()).collect()
    }

    pub fn lock(&mut self) {
        self.state = State::Locked; // drops DEK -> zeroized
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }
    pub fn records(&self) -> &[Record] {
        &self.records
    }
    // NB: no public `header_mut`/`set_records`. Authenticated state (header +
    // record set) is only mutated through `add`/`save`, which recompute the MAC.
    // Exposing raw mutators would let a caller desync the in-memory state from
    // its MAC. Removed as a deliberate encapsulation boundary.

    /// Persist the vault to disk. Requires the vault to be unlocked, since
    /// writing a fresh header MAC needs the DEK. On-disk layout:
    /// `u32 len(header) || header_bytes || u32 num_records ||
    ///  [ id(16 LE) || u32 len(name) || name_utf8 || u32 len(ct) || ct ]*`
    ///
    /// Writes are atomic: the serialized vault is written to a unique temp
    /// file in the same directory as `path`, then renamed into place.
    /// `std::fs::rename` replaces the destination atomically (on both
    /// Windows and Unix, within a single filesystem), so a crash mid-write
    /// leaves the previous vault file intact instead of a truncated/corrupt
    /// one -- important here since the wrapped DEK lives only in this file's
    /// header, so a partial write would otherwise be unrecoverable data loss.
    pub fn save(&self, path: &Path) -> Result<()> {
        let dek = self.dek()?;

        let mut header = self.header.clone();
        header.header_mac = header.compute_mac(dek, &self.records);
        let header_bytes = header.to_bytes();

        let mut out = Vec::new();
        put_bytes(&mut out, &header_bytes);
        put_u32(&mut out, self.records.len() as u32);
        for r in &self.records {
            r.to_bytes(&mut out);
        }

        let tmp = Self::temp_path_for(path);
        if let Err(e) = std::fs::write(&tmp, &out) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(())
    }

    /// Build a unique temp-file path in the same directory as `path` (so the
    /// final rename stays on one filesystem, which is required for it to be
    /// atomic).
    fn temp_path_for(path: &Path) -> std::path::PathBuf {
        let mut rand_bytes = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut rand_bytes);
        let mut suffix = String::with_capacity(16);
        for b in rand_bytes {
            suffix.push_str(&format!("{b:02x}"));
        }

        let mut file_name = path
            .file_name()
            .map(|f| f.to_os_string())
            .unwrap_or_else(|| std::ffi::OsString::from("vault"));
        file_name.push(format!(".tmp-{}-{}", std::process::id(), suffix));

        match path.parent() {
            Some(dir) => dir.join(&file_name),
            None => std::path::PathBuf::from(&file_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;
    use crate::secret::{SecretBytes, SecretString};

    fn test_header() -> VaultHeader {
        VaultHeader {
            magic: *b"ZTSV",
            format_version: FORMAT_VERSION,
            hardware_bound: false,
            aead_id: 1,
            kdf: Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [9u8; 16] },
            pcr_selection: vec![],
            tpm_wrap: None,
            dek_wrap: vec![1, 2, 3],
            recovery_wrap: None,
            recovery_kdf: None,
            header_mac: [0u8; 32],
        }
    }

    #[test]
    fn header_roundtrips() {
        let mut h = test_header();
        let dek = SecretBytes::from_exact(&[4u8; 32]);
        h.header_mac = h.compute_mac(&dek, &[]);
        let bytes = h.to_bytes();
        let back = VaultHeader::from_bytes(&bytes).unwrap();
        assert_eq!(back.magic, *b"ZTSV");
        assert_eq!(back.dek_wrap, vec![1, 2, 3]);
        assert!(back.verify_mac(&dek, &[]));
    }

    #[test]
    fn header_mac_detects_tamper() {
        let mut h = test_header();
        let dek = SecretBytes::from_exact(&[4u8; 32]);
        h.header_mac = h.compute_mac(&dek, &[]);
        let mut bytes = h.to_bytes();
        // flip hardware_bound byte region -> MAC must fail
        let idx = 6;
        bytes[idx] ^= 0x01;
        let back = VaultHeader::from_bytes(&bytes).unwrap();
        assert!(!back.verify_mac(&dek, &[]));
    }

    #[test]
    fn header_mac_detects_record_relabel_delete_and_reorder() {
        let dek = SecretBytes::from_exact(&[4u8; 32]);
        let mut h = test_header();
        let recs = vec![Record { id: 1, name: "email".into(), ciphertext: vec![9, 9] }];
        h.header_mac = h.compute_mac(&dek, &recs);

        // relabel same (id, ciphertext) under a new name -> fails
        let relabeled = vec![Record { id: 1, name: "other".into(), ciphertext: vec![9, 9] }];
        assert!(!h.verify_mac(&dek, &relabeled));
        // delete the record -> fails
        assert!(!h.verify_mac(&dek, &[]));
        // unchanged set still verifies
        assert!(h.verify_mac(&dek, &recs));

        // reorder two records -> fails
        let two = vec![
            Record { id: 1, name: "a".into(), ciphertext: vec![1] },
            Record { id: 2, name: "b".into(), ciphertext: vec![2] },
        ];
        h.header_mac = h.compute_mac(&dek, &two);
        let swapped = vec![
            Record { id: 2, name: "b".into(), ciphertext: vec![2] },
            Record { id: 1, name: "a".into(), ciphertext: vec![1] },
        ];
        assert!(!h.verify_mac(&dek, &swapped));
        assert!(h.verify_mac(&dek, &two));
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

    #[test]
    fn save_then_load_roundtrips() {
        let dek = SecretBytes::from_exact(&[6u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("email", SecretString::from_string("hunter2".into())).unwrap();
        v.add("bank_pin", SecretString::from_string("1234".into())).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("vaultcore_test_{}.ztsv", std::process::id()));
        v.save(&path).unwrap();

        let locked = LockedVault::load(&path).unwrap();
        std::fs::remove_file(&path).ok();

        let dek2 = SecretBytes::from_exact(&[6u8; 32]);
        let unlocked = locked.unlock_with_dek(dek2).unwrap();
        assert!(unlocked
            .header()
            .verify_mac(&SecretBytes::from_exact(&[6u8; 32]), unlocked.records()));
        assert_eq!(unlocked.records().len(), 2);
        assert_eq!(unlocked.get("email").unwrap().expose_str(), "hunter2");
        assert_eq!(unlocked.get("bank_pin").unwrap().expose_str(), "1234");
    }

    #[test]
    fn unlock_with_wrong_dek_fails() {
        let dek = SecretBytes::from_exact(&[7u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("email", SecretString::from_string("hunter2".into())).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("vaultcore_test_wrongdek_{}.ztsv", std::process::id()));
        v.save(&path).unwrap();

        let locked = LockedVault::load(&path).unwrap();
        std::fs::remove_file(&path).ok();

        let wrong_dek = SecretBytes::from_exact(&[8u8; 32]);
        let result = locked.unlock_with_dek(wrong_dek);
        assert!(matches!(result, Err(crate::Error::AuthFailed)));
    }

    #[test]
    fn v2_two_factor_end_to_end_with_recovery() {
        let dek = SecretBytes::generate(32);
        let pass = SecretString::from_string("unlock".into());
        let rec = SecretString::from_string("recovery".into());
        let tpm = SecretBytes::from_exact(&[5u8; 32]); // stand-in for the TPM secret
        let kdf = Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [1u8; 16] };
        let rkdf = Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [2u8; 16] };

        let dek_wrap = crate::envelope::wrap_dek(&dek, &pass, &kdf, Some(&tpm)).unwrap();
        let rec_wrap = crate::envelope::wrap_dek_recovery(&dek, &rec, &rkdf).unwrap();
        let header =
            VaultHeader::new_v2(true, kdf, Some(vec![0xAA; 8]), dek_wrap, Some((rec_wrap, rkdf)));

        let mut v = Vault::new_unlocked(SecretBytes::from_exact(dek.expose()), header);
        v.add("email", SecretString::from_string("hunter2".into())).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("vaultcore_v2_{}.ztsv", std::process::id()));
        v.save(&path).unwrap();

        // Primary two-factor unlock recovers the secret.
        let locked = LockedVault::load(&path).unwrap();
        let unlocked = locked.unlock_two_factor(&pass, Some(&tpm)).unwrap();
        assert_eq!(unlocked.get("email").unwrap().expose_str(), "hunter2");

        // Wrong passphrase -> fails closed.
        let locked = LockedVault::load(&path).unwrap();
        assert!(locked
            .unlock_two_factor(&SecretString::from_string("wrong".into()), Some(&tpm))
            .is_err());

        // Missing TPM factor (e.g. drive moved to another machine) -> fails closed.
        let locked = LockedVault::load(&path).unwrap();
        assert!(locked.unlock_two_factor(&pass, None).is_err());

        // Recovery path (single factor) recovers the secret.
        let locked = LockedVault::load(&path).unwrap();
        let unlocked = locked.unlock_recovery(&rec).unwrap();
        assert_eq!(unlocked.get("email").unwrap().expose_str(), "hunter2");

        // Recovery with the wrong passphrase -> fails closed.
        let locked = LockedVault::load(&path).unwrap();
        assert!(locked
            .unlock_recovery(&SecretString::from_string("bad".into()))
            .is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_rejects_huge_record_count_without_huge_alloc() {
        // A tiny file that claims ~4 billion records but provides no record
        // bodies must fail cleanly (Format error) rather than pre-allocating a
        // giant Vec. With the untrusted count no longer driving `with_capacity`,
        // parsing bails on the first missing record.
        let h = test_header();
        let header_bytes = h.to_bytes();
        let mut data = Vec::new();
        put_bytes(&mut data, &header_bytes); // u32 len || header
        put_u32(&mut data, u32::MAX); // claim ~4 billion records, provide none

        let mut path = std::env::temp_dir();
        path.push(format!("vaultcore_test_dos_{}.ztsv", std::process::id()));
        std::fs::write(&path, &data).unwrap();
        let r = LockedVault::load(&path);
        std::fs::remove_file(&path).ok();
        assert!(matches!(r, Err(crate::Error::Format(_))));
    }

    #[test]
    fn save_requires_unlocked() {
        let dek = SecretBytes::from_exact(&[9u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.lock();
        let mut path = std::env::temp_dir();
        path.push(format!("vaultcore_test_locked_{}.ztsv", std::process::id()));
        assert!(matches!(v.save(&path), Err(crate::Error::Locked)));
    }

    /// Helper: list `*.tmp-*` entries left behind in `dir` by `save`'s
    /// temp-file-then-rename dance. Should always be empty after `save`
    /// returns (success or failure).
    fn leftover_tmp_files(dir: &std::path::Path, stem: &str) -> Vec<std::path::PathBuf> {
        let mut leftovers = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with(stem) && name.contains(".tmp-") {
                    leftovers.push(entry.path());
                }
            }
        }
        leftovers
    }

    #[test]
    fn save_is_atomic_and_leaves_no_temp() {
        let dek = SecretBytes::from_exact(&[10u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("email", SecretString::from_string("hunter2".into())).unwrap();

        let dir = std::env::temp_dir();
        let stem = format!("vaultcore_test_atomic_{}", std::process::id());
        let mut path = dir.clone();
        path.push(format!("{stem}.ztsv"));
        // Clean up any stray file from a previous failed run.
        let _ = std::fs::remove_file(&path);

        // First save: creates the vault file.
        v.save(&path).unwrap();
        assert!(path.exists());
        assert!(leftover_tmp_files(&dir, &stem).is_empty());

        // Second save (overwrite of an existing vault): rename-over-existing
        // must succeed and still leave no temp residue.
        v.add("bank_pin", SecretString::from_string("1234".into())).unwrap();
        v.save(&path).unwrap();
        assert!(leftover_tmp_files(&dir, &stem).is_empty());

        // The file loads and verifies after the (second, overwriting) save.
        let locked = LockedVault::load(&path).unwrap();
        std::fs::remove_file(&path).ok();

        let dek2 = SecretBytes::from_exact(&[10u8; 32]);
        let unlocked = locked.unlock_with_dek(dek2).unwrap();
        assert!(unlocked
            .header()
            .verify_mac(&SecretBytes::from_exact(&[10u8; 32]), unlocked.records()));
        assert_eq!(unlocked.records().len(), 2);
        assert_eq!(unlocked.get("email").unwrap().expose_str(), "hunter2");
        assert_eq!(unlocked.get("bank_pin").unwrap().expose_str(), "1234");
    }
}
