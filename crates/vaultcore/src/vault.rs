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

#[derive(Clone)]
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
        put_bytes(&mut b, &self.recovery_wrap);
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
        let hardware_bound = c.u8()? != 0;
        let aead_id = c.u8()?;
        let kdf = Argon2Params {
            mem_kib: c.u32()?,
            time: c.u32()?,
            parallelism: c.u32()?,
            salt: c
                .take(16)?
                .try_into()
                .map_err(|_| Error::Format("salt".into()))?,
        };
        let npcr = c.u32()? as usize;
        let mut pcr_selection = Vec::with_capacity(npcr.min(1 << 20));
        for _ in 0..npcr {
            pcr_selection.push(c.u32()?);
        }
        let tpm_wrap = if c.u8()? == 1 { Some(c.bytes()?) } else { None };
        let recovery_wrap = c.bytes()?;
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
            recovery_wrap,
            header_mac,
        })
    }

    fn mac_input(&self) -> Vec<u8> {
        let mut h = self.clone();
        h.header_mac = [0u8; 32];
        h.to_bytes()
    }

    pub fn compute_mac(&self, dek: &SecretBytes) -> [u8; 32] {
        let mk = crypto::hkdf_subkey(dek, b"header-mac", KEY_LEN);
        use hkdf::hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut m = <Hmac<Sha256>>::new_from_slice(mk.expose()).expect("hmac accepts any key len");
        m.update(&self.mac_input());
        m.finalize().into_bytes().into()
    }

    pub fn verify_mac(&self, dek: &SecretBytes) -> bool {
        use subtle::ConstantTimeEq;
        self.compute_mac(dek).ct_eq(&self.header_mac).into()
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
        let mut records = Vec::with_capacity(num_records.min(1 << 20));
        for _ in 0..num_records {
            records.push(Record::from_cursor(&mut c)?);
        }
        Ok(LockedVault { header, records })
    }

    /// Verify the header MAC against the supplied DEK and, on success,
    /// return an unlocked `Vault`. Fails closed: on MAC mismatch this
    /// returns `Error::AuthFailed` and no usable vault is produced.
    pub fn unlock_with_dek(self, dek: SecretBytes) -> Result<Vault> {
        if !self.header.verify_mac(&dek) {
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
        let ct = crypto::aead_seal(
            &rk,
            &Self::aad(id, self.header.format_version),
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
        let pt = crypto::aead_open(&rk, &Self::aad(rec.id, self.header.format_version), &rec.ciphertext)?;
        // pt is SecretBytes; wrap as SecretString
        let s = String::from_utf8(pt.expose().to_vec()).map_err(|_| Error::Format("utf8".into()))?;
        Ok(SecretString::from_string(s))
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
    pub fn header_mut(&mut self) -> &mut VaultHeader {
        &mut self.header
    }
    pub fn records(&self) -> &[Record] {
        &self.records
    }
    pub fn set_records(&mut self, r: Vec<Record>) {
        self.records = r;
    }

    /// Persist the vault to disk. Requires the vault to be unlocked, since
    /// writing a fresh header MAC needs the DEK. On-disk layout:
    /// `u32 len(header) || header_bytes || u32 num_records ||
    ///  [ id(16 LE) || u32 len(name) || name_utf8 || u32 len(ct) || ct ]*`
    pub fn save(&self, path: &Path) -> Result<()> {
        let dek = self.dek()?;

        let mut header = self.header.clone();
        header.header_mac = header.compute_mac(dek);
        let header_bytes = header.to_bytes();

        let mut out = Vec::new();
        put_bytes(&mut out, &header_bytes);
        put_u32(&mut out, self.records.len() as u32);
        for r in &self.records {
            r.to_bytes(&mut out);
        }
        std::fs::write(path, out)?;
        Ok(())
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
        assert!(unlocked.header().verify_mac(&SecretBytes::from_exact(&[6u8; 32])));
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
    fn save_requires_unlocked() {
        let dek = SecretBytes::from_exact(&[9u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.lock();
        let mut path = std::env::temp_dir();
        path.push(format!("vaultcore_test_locked_{}.ztsv", std::process::id()));
        assert!(matches!(v.save(&path), Err(crate::Error::Locked)));
    }
}
