//! On-disk vault format and lock/unlock state machine.
//!
//! Layout: a versioned, authenticated header (HMAC-SHA256 over the header
//! bytes, keyed by an HKDF subkey of the DEK) followed by a sequence of
//! records. As of format v3 each record is `id ‖ name_ct ‖ value_ct`, where the
//! record NAME *and* value are each encrypted with XChaCha20-Poly1305 under
//! distinct per-record HKDF subkeys and padded to fixed size buckets, and the
//! record set is padded with indistinguishable tombstone records up to a count
//! bucket. A stolen `.ztsv` therefore leaks neither what accounts exist, their
//! sizes, nor (beyond a coarse bucket) how many there are. Tamper anywhere in the
//! header or a record must fail closed (`Error::AuthFailed`), never silently
//! return partial or wrong data.

use crate::crypto::{self, Argon2Params, KEY_LEN};
use crate::secret::{ProtectedDek, SecretBytes, SecretString};
use crate::{Error, Result};
use std::path::Path;

const MAGIC: [u8; 4] = *b"ZTSV";

// Upper bounds on the Argon2id cost parameters accepted from a vault header.
// These parameters are attacker-controllable (they live in the untrusted header
// and MUST be consumed to derive the KEK *before* the header MAC can be checked),
// so an unbounded `mem_kib`/`time` would let a hostile `.ztsv` force a
// multi-hundred-GiB allocation or unbounded compute at unlock -- a pre-auth
// memory/CPU DoS. The ceilings are generous versus `default_tuned` (64 MiB / t=3)
// yet keep the worst case survivable. A header outside these bounds is rejected
// at parse time, before any Argon2 work happens.
pub(crate) const MAX_ARGON2_MEM_KIB: u32 = 1 << 20; // 1 GiB
const MAX_ARGON2_TIME: u32 = 64;
const MAX_ARGON2_PARALLELISM: u32 = 64;
/// Current on-disk format version. v3 = encrypted record names + padded name/value
/// sizes + tombstone-padded record count (see this module's docs). The two-factor
/// DEK envelope (see `envelope.rs`) is unchanged. Older formats (v1 single-factor,
/// v2 plaintext-name) are intentionally NOT read by this build — there is no
/// migration path (consistent with this project's "recreate to upgrade" stance,
/// which keeps the parser to a single format and avoids resurrecting legacy
/// layouts); a pre-v3 vault must be recreated with `vaultctl init` or the GUI.
pub const FORMAT_VERSION: u16 = 3;

/// Record names are padded to a multiple of this many bytes before encryption, so
/// a record's on-disk `name_ct` length reveals only a coarse bucket, not the exact
/// name length.
const NAME_BUCKET: usize = 64;
/// Record values are padded to a multiple of this many bytes before encryption.
const VALUE_BUCKET: usize = 256;
/// The record set is padded with tombstones up to a multiple of this many records
/// (minimum one bucket), so the on-disk record count reveals only a coarse bucket.
const COUNT_BUCKET: usize = 8;
/// Defensive ceiling on a decoded name length (from a decrypted, authenticated
/// plaintext) — guards against a corrupt length prefix driving a bad slice.
const MAX_NAME_LEN: usize = 4096;

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

/// SHA-256 fingerprint of the raw vault-file bytes, used only for
/// optimistic-concurrency detection in `save` (loud-fail on a concurrent
/// overwrite). This is not a security control -- integrity is the header MAC.
fn file_fingerprint(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
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
            // Only the current format is read. Older layouts (v1 single-factor, v2
            // plaintext-name) predate this one; this build intentionally carries no
            // legacy parser (reduced attack surface / one format to reason about),
            // so an older vault must be recreated.
            return Err(Error::Format(format!(
                "unsupported vault format version {format_version} (this build reads v{FORMAT_VERSION}); \
                 a pre-v{FORMAT_VERSION} vault must be recreated with `vaultctl init`"
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

    /// HMAC over the header bytes and the full on-disk record set (count, then each
    /// raw record's id, `name_ct`, `value_ct` in order). Authenticates every byte
    /// that hits the disk — including the tombstone padding — so any relabel /
    /// delete / reorder / inject fails closed at unlock.
    pub fn compute_mac(&self, dek: &SecretBytes, records: &[RawRecord]) -> [u8; 32] {
        let mk = crypto::hkdf_subkey(dek, b"header-mac", KEY_LEN);
        use hkdf::hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut m = <Hmac<Sha256>>::new_from_slice(mk.expose()).expect("hmac accepts any key len");
        m.update(&self.mac_input());
        // authenticate the record set: count, then each record in order
        m.update(&(records.len() as u32).to_le_bytes());
        for r in records {
            m.update(&r.id.to_le_bytes());
            m.update(&(r.name_ct.len() as u32).to_le_bytes());
            m.update(&r.name_ct);
            m.update(&(r.value_ct.len() as u32).to_le_bytes());
            m.update(&r.value_ct);
        }
        m.finalize().into_bytes().into()
    }

    pub fn verify_mac(&self, dek: &SecretBytes, records: &[RawRecord]) -> bool {
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
        let mem_kib = self.u32()?;
        let time = self.u32()?;
        let parallelism = self.u32()?;
        // Reject implausible cost parameters before they can drive an Argon2
        // allocation/compute on the pre-authentication unlock path (DoS).
        if mem_kib > MAX_ARGON2_MEM_KIB
            || time > MAX_ARGON2_TIME
            || parallelism > MAX_ARGON2_PARALLELISM
        {
            return Err(Error::Format(format!(
                "argon2 parameters out of range (mem_kib={mem_kib}, time={time}, \
                 parallelism={parallelism})"
            )));
        }
        Ok(Argon2Params {
            mem_kib,
            time,
            parallelism,
            salt: self
                .take(16)?
                .try_into()
                .map_err(|_| Error::Format("argon2 salt".into()))?,
        })
    }
}

/// A record as it lives on disk (and in a still-locked vault): an opaque id plus
/// the encrypted, padded name and value. Nothing here is plaintext.
pub struct RawRecord {
    pub id: u128,
    pub name_ct: Vec<u8>,
    pub value_ct: Vec<u8>,
}

impl RawRecord {
    fn to_bytes(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.id.to_le_bytes());
        put_bytes(b, &self.name_ct);
        put_bytes(b, &self.value_ct);
    }

    fn from_cursor(c: &mut Cursor) -> Result<Self> {
        let id_bytes: [u8; 16] = c
            .take(16)?
            .try_into()
            .map_err(|_| Error::Format("record id".into()))?;
        let id = u128::from_le_bytes(id_bytes);
        let name_ct = c.bytes()?;
        let value_ct = c.bytes()?;
        Ok(RawRecord { id, name_ct, value_ct })
    }
}

/// A record in an UNLOCKED vault: its name is decrypted (for lookup/listing), but
/// its value stays encrypted (`value_ct`) in RAM until `get` is called — so an
/// unlocked session never holds every secret value in plaintext at once.
pub struct Record {
    pub id: u128,
    pub name: String,
    pub value_ct: Vec<u8>,
}

// --- v3 record encryption / padding helpers ---

fn padded_len(unpadded: usize, bucket: usize) -> usize {
    unpadded.div_ceil(bucket).max(1) * bucket
}

/// AAD binding a record's name/value ciphertext to its id and the format version.
fn record_aad(id: u128, version: u16) -> Vec<u8> {
    let mut a = Vec::with_capacity(18);
    a.extend_from_slice(&id.to_le_bytes());
    a.extend_from_slice(&version.to_le_bytes());
    a
}

fn subkey(dek: &SecretBytes, label: &[u8], id: u128) -> SecretBytes {
    let mut info = Vec::with_capacity(label.len() + 16);
    info.extend_from_slice(label);
    info.extend_from_slice(&id.to_le_bytes());
    crypto::hkdf_subkey(dek, &info, KEY_LEN)
}

/// Encode `[kind ‖ len ‖ name ‖ zero-pad]` to a `NAME_BUCKET` multiple. `kind` is
/// 0 for a real record, 1 for a tombstone (name empty).
fn encode_name_plaintext(kind: u8, name: &str) -> Vec<u8> {
    let nb = name.as_bytes();
    let target = padded_len(1 + 4 + nb.len(), NAME_BUCKET);
    let mut p = Vec::with_capacity(target);
    p.push(kind);
    p.extend_from_slice(&(nb.len() as u32).to_le_bytes());
    p.extend_from_slice(nb);
    p.resize(target, 0);
    p
}

/// Returns `Ok(None)` for a tombstone, `Ok(Some(name))` for a real record.
fn decode_name_plaintext(p: &[u8]) -> Result<Option<String>> {
    if p.len() < 5 {
        return Err(Error::Format("name plaintext too short".into()));
    }
    let kind = p[0];
    let len = u32::from_le_bytes(p[1..5].try_into().unwrap()) as usize;
    if len > MAX_NAME_LEN || 5 + len > p.len() {
        return Err(Error::Format("name length out of range".into()));
    }
    match kind {
        1 => Ok(None),
        0 => {
            let name = std::str::from_utf8(&p[5..5 + len])
                .map_err(|_| Error::Format("record name utf8".into()))?
                .to_string();
            Ok(Some(name))
        }
        _ => Err(Error::Format("bad record kind".into())),
    }
}

/// Build `[len ‖ value ‖ zero-pad]` to a `VALUE_BUCKET` multiple, in a page-locked
/// secret buffer.
fn encode_value_plaintext(value: &[u8]) -> SecretBytes {
    let target = padded_len(4 + value.len(), VALUE_BUCKET);
    let mut sb = SecretBytes::zeros(target);
    let m = sb.expose_mut();
    m[0..4].copy_from_slice(&(value.len() as u32).to_le_bytes());
    m[4..4 + value.len()].copy_from_slice(value);
    sb
}

fn decode_value_plaintext(p: &[u8]) -> Result<SecretBytes> {
    if p.len() < 4 {
        return Err(Error::Format("value plaintext too short".into()));
    }
    let len = u32::from_le_bytes(p[0..4].try_into().unwrap()) as usize;
    if 4 + len > p.len() {
        return Err(Error::Format("value length out of range".into()));
    }
    Ok(SecretBytes::from_exact(&p[4..4 + len]))
}

fn seal_name(dek: &SecretBytes, id: u128, version: u16, kind: u8, name: &str) -> Result<Vec<u8>> {
    crypto::aead_seal(
        &subkey(dek, b"record-name-v3", id),
        &record_aad(id, version),
        &encode_name_plaintext(kind, name),
    )
}

fn seal_value(dek: &SecretBytes, id: u128, version: u16, value: &[u8]) -> Result<Vec<u8>> {
    crypto::aead_seal(
        &subkey(dek, b"record-value-v3", id),
        &record_aad(id, version),
        encode_value_plaintext(value).expose(),
    )
}

fn open_name(dek: &SecretBytes, id: u128, version: u16, name_ct: &[u8]) -> Result<Option<String>> {
    let pt = crypto::aead_open(&subkey(dek, b"record-name-v3", id), &record_aad(id, version), name_ct)?;
    decode_name_plaintext(pt.expose())
}

fn random_id() -> u128 {
    let mut b = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    u128::from_le_bytes(b)
}

/// Fisher–Yates shuffle so real vs tombstone record positions don't correlate
/// across saves (order carries no meaning — records are keyed by name after
/// decryption; the header MAC still binds the exact on-disk order).
fn shuffle_raw(v: &mut [RawRecord]) {
    for i in (1..v.len()).rev() {
        let mut b = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
        let j = (u64::from_le_bytes(b) % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

enum State {
    Locked,
    /// The DEK, held encrypted at rest in RAM (see `ProtectedDek`) and revealed
    /// transiently only for the duration of a single crypto operation.
    Unlocked(ProtectedDek),
}

/// A vault whose header and record framing are known but which has not been
/// authenticated/decrypted yet. Holds no DEK and no plaintext.
pub struct LockedVault {
    header: VaultHeader,
    records: Vec<RawRecord>,
    /// SHA-256 of the exact bytes read from disk, for optimistic-concurrency
    /// detection when a derived `Vault` is later saved (see `Vault::save`).
    fingerprint: [u8; 32],
}

impl LockedVault {
    /// Read a vault file from disk and parse its header + record framing,
    /// without authenticating or decrypting anything.
    pub fn load(path: &Path) -> Result<LockedVault> {
        let data = std::fs::read(path)?;
        let fingerprint = file_fingerprint(&data);
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
            records.push(RawRecord::from_cursor(&mut c)?);
        }
        Ok(LockedVault { header, records, fingerprint })
    }

    /// Verify the header MAC against the supplied DEK and, on success, decrypt
    /// every record name (dropping tombstones) to produce the unlocked `Vault`.
    /// Fails closed: on MAC mismatch this returns `Error::AuthFailed` and no usable
    /// vault is produced. Values are NOT decrypted here — they stay as `value_ct`
    /// until `get`, so an unlocked session never holds all secret values at once.
    pub fn unlock_with_dek(self, dek: SecretBytes) -> Result<Vault> {
        if !self.header.verify_mac(&dek, &self.records) {
            return Err(Error::AuthFailed);
        }
        let version = self.header.format_version;
        let mut records = Vec::new();
        for raw in &self.records {
            // MAC already authenticated `name_ct`, so a correct-DEK open succeeds;
            // a failure fails closed rather than guessing.
            if let Some(name) = open_name(&dek, raw.id, version, &raw.name_ct)? {
                records.push(Record { id: raw.id, name, value_ct: raw.value_ct.clone() });
            }
            // `None` => tombstone padding: dropped from the logical view.
        }
        Ok(Vault {
            header: self.header,
            records,
            state: State::Unlocked(ProtectedDek::new(dek)),
            loaded_fingerprint: Some(self.fingerprint),
        })
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Number of raw (encrypted) records on disk, including tombstone padding.
    /// Test-only: the logical name list requires the DEK (names are encrypted).
    #[cfg(test)]
    pub fn raw_record_count(&self) -> usize {
        self.records.len()
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
    /// SHA-256 of the file this vault was loaded from, or `None` for a vault
    /// built in memory (`new_unlocked`). Drives the optimistic-concurrency
    /// check in `save`.
    loaded_fingerprint: Option<[u8; 32]>,
}

impl Vault {
    pub fn new_unlocked(dek: SecretBytes, header: VaultHeader) -> Self {
        Vault {
            header,
            records: Vec::new(),
            state: State::Unlocked(ProtectedDek::new(dek)),
            loaded_fingerprint: None,
        }
    }
    /// Reveal a transient plaintext copy of the DEK for one operation. Returns an
    /// owned, page-locked `SecretBytes` that the caller drops (zeroized) as soon as
    /// the operation completes, so the plaintext key exists in RAM only fleetingly.
    fn dek(&self) -> Result<SecretBytes> {
        match &self.state {
            State::Unlocked(d) => Ok(d.reveal()),
            State::Locked => Err(Error::Locked),
        }
    }
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, State::Unlocked(_))
    }

    /// Add a NEW secret. Fails with [`Error::Duplicate`] if `name` already
    /// exists, so a second `add` can never silently shadow an existing record
    /// (the read path returns the first match, which would otherwise make the
    /// new value permanently unreachable). Use [`Vault::upsert`] to rotate a
    /// secret in place.
    pub fn add(&mut self, name: &str, value: SecretString) -> Result<()> {
        if self.records.iter().any(|r| r.name == name) {
            return Err(Error::Duplicate(name.to_string()));
        }
        self.insert_record(name, value)
    }

    /// Add `name`, or replace it in place if it already exists (rotation). Any
    /// pre-existing record(s) with this name are removed first, so the result is
    /// exactly one record for `name` holding the new value.
    pub fn upsert(&mut self, name: &str, value: SecretString) -> Result<()> {
        self.records.retain(|r| r.name != name);
        self.insert_record(name, value)
    }

    /// Remove every record named `name`. Returns `true` if anything was removed.
    /// The change is persisted (and the header MAC recomputed) by the next
    /// [`Vault::save`].
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.records.len();
        self.records.retain(|r| r.name != name);
        self.records.len() != before
    }

    /// Encrypt `value` (padded) under a fresh per-record value key and append the
    /// record, keeping its name in plaintext in memory for lookup. Assumes the
    /// caller has already enforced whatever name-uniqueness policy applies. The
    /// name is encrypted only when the vault is saved (see `save`).
    fn insert_record(&mut self, name: &str, value: SecretString) -> Result<()> {
        let dek = self.dek()?;
        let id = random_id();
        let value_ct =
            seal_value(&dek, id, self.header.format_version, value.expose_str().as_bytes())?;
        self.records.push(Record { id, name: name.to_string(), value_ct });
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<SecretString> {
        let dek = self.dek()?;
        let rec = self
            .records
            .iter()
            .find(|r| r.name == name)
            .ok_or_else(|| Error::NotFound(name.to_string()))?;
        let padded = crypto::aead_open(
            &subkey(&dek, b"record-value-v3", rec.id),
            &record_aad(rec.id, self.header.format_version),
            &rec.value_ct,
        )?;
        // `padded` is the padded value plaintext (page-locked); slice out the exact
        // value into a fresh locked buffer and wrap it. `padded` drops zeroized.
        let value = decode_value_plaintext(padded.expose())?;
        SecretString::from_secret_bytes(value)
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
    /// writing a fresh header MAC (and re-encrypting names + generating tombstones)
    /// needs the DEK. On-disk layout:
    /// `u32 len(header) || header_bytes || u32 num_records ||
    ///  [ id(16 LE) || u32 len(name_ct) || name_ct || u32 len(value_ct) || value_ct ]*`
    /// where `num_records` includes tombstone padding and each `*_ct` is an
    /// XChaCha20-Poly1305 blob over the padded name/value.
    ///
    /// Writes are atomic and durable: the serialized vault is written to a
    /// unique temp file in the same directory as `path`, `fsync`ed, then renamed
    /// into place. `std::fs::rename` replaces the destination atomically (on both
    /// Windows and Unix, within a single filesystem), so the previous vault file
    /// stays intact until the new one is fully on disk. The `sync_all` before the
    /// rename is what makes this power-loss-safe and not merely crash-safe:
    /// without it a power failure could commit the rename while the temp file's
    /// data blocks were still unflushed, destroying the only copy of the wrapped
    /// DEK (which lives solely in this file's header).
    pub fn save(&mut self, path: &Path) -> Result<()> {
        let dek = self.dek()?;
        let version = self.header.format_version;

        // Build the on-disk raw record set: re-encrypt each real record's name
        // under a fresh nonce, keep its already-encrypted value, then pad with
        // indistinguishable tombstone records up to a count bucket and shuffle, so
        // a stolen file leaks neither the names, the sizes, nor (beyond a coarse
        // bucket) the count — and real vs tombstone positions don't correlate.
        let target = padded_len(self.records.len(), COUNT_BUCKET);
        let mut raws: Vec<RawRecord> = Vec::with_capacity(target);
        for r in &self.records {
            let name_ct = seal_name(&dek, r.id, version, 0, &r.name)?;
            raws.push(RawRecord { id: r.id, name_ct, value_ct: r.value_ct.clone() });
        }
        while raws.len() < target {
            let id = random_id();
            let name_ct = seal_name(&dek, id, version, 1, "")?;
            let value_ct = seal_value(&dek, id, version, &[])?;
            raws.push(RawRecord { id, name_ct, value_ct });
        }
        shuffle_raw(&mut raws);

        let mut header = self.header.clone();
        header.header_mac = header.compute_mac(&dek, &raws);
        let header_bytes = header.to_bytes();

        let mut out = Vec::new();
        put_bytes(&mut out, &header_bytes);
        put_u32(&mut out, raws.len() as u32);
        for r in &raws {
            r.to_bytes(&mut out);
        }

        // Optimistic concurrency (F6): if this vault was loaded from disk and the
        // file has since changed, another writer modified it after our load.
        // Refuse rather than silently overwrite their change (a lost update).
        // This narrows the race to the window between this check and the rename.
        if let Some(expected) = self.loaded_fingerprint {
            if let Ok(current) = std::fs::read(path) {
                if file_fingerprint(&current) != expected {
                    return Err(Error::Provider(
                        "vault changed on disk since it was loaded; aborting to avoid \
                         overwriting a concurrent modification"
                            .into(),
                    ));
                }
            }
            // If the file is gone, there is nothing to clobber; proceed.
        }

        let tmp = Self::temp_path_for(path);
        if let Err(e) = Self::write_synced(&tmp, &out) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        // The file now holds exactly `out`; refresh the fingerprint so a later
        // save from this same (long-lived) vault compares against what we just
        // wrote rather than the stale load-time contents.
        self.loaded_fingerprint = Some(file_fingerprint(&out));
        Ok(())
    }

    /// Write `bytes` to `path` and `fsync` the file (data + metadata) before
    /// returning, so a following rename produces a durable, fully-written file.
    fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::create(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
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
        let raw =
            |id, n: &[u8], v: &[u8]| RawRecord { id, name_ct: n.to_vec(), value_ct: v.to_vec() };
        let recs = vec![raw(1, &[9, 9], &[7])];
        h.header_mac = h.compute_mac(&dek, &recs);

        // tamper the encrypted name blob (a relabel attempt) -> fails
        let relabeled = vec![raw(1, &[8, 8], &[7])];
        assert!(!h.verify_mac(&dek, &relabeled));
        // delete the record -> fails
        assert!(!h.verify_mac(&dek, &[]));
        // unchanged set still verifies
        assert!(h.verify_mac(&dek, &recs));

        // reorder two records -> fails
        let two = vec![raw(1, &[1], &[1]), raw(2, &[2], &[2])];
        h.header_mac = h.compute_mac(&dek, &two);
        let swapped = vec![raw(2, &[2], &[2]), raw(1, &[1], &[1])];
        assert!(!h.verify_mac(&dek, &swapped));
        assert!(h.verify_mac(&dek, &two));
    }

    #[test]
    fn add_rejects_duplicate_name() {
        // F1: adding an existing name must NOT silently shadow. The original
        // value stays reachable; no duplicate is created.
        let dek = SecretBytes::from_exact(&[5u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("email", SecretString::from_string("first".into())).unwrap();
        let dup = v.add("email", SecretString::from_string("second".into()));
        assert!(matches!(dup, Err(crate::Error::Duplicate(_))));
        assert_eq!(v.list(), vec!["email"]);
        assert_eq!(v.get("email").unwrap().expose_str(), "first");
    }

    #[test]
    fn upsert_replaces_existing_and_adds_new() {
        // F1: upsert rotates a secret in place (get returns the new value, no
        // duplicate) and also adds when the name is absent.
        let dek = SecretBytes::from_exact(&[5u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("email", SecretString::from_string("old".into())).unwrap();
        v.upsert("email", SecretString::from_string("new".into())).unwrap();
        assert_eq!(v.list(), vec!["email"]);
        assert_eq!(v.get("email").unwrap().expose_str(), "new");

        v.upsert("bank", SecretString::from_string("1234".into())).unwrap();
        assert_eq!(v.get("bank").unwrap().expose_str(), "1234");
    }

    #[test]
    fn remove_deletes_record_and_is_idempotent() {
        // F1: removing a record makes it unreadable (NotFound); removing a
        // missing name is a no-op that reports "nothing removed".
        let dek = SecretBytes::from_exact(&[5u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("email", SecretString::from_string("a".into())).unwrap();
        assert!(v.remove("email"));
        assert!(matches!(v.get("email"), Err(crate::Error::NotFound(_))));
        assert!(!v.remove("email"));
    }

    #[test]
    fn load_rejects_out_of_range_argon2_params() {
        // F2: absurd KDF cost parameters from an untrusted header must be
        // rejected at parse time, BEFORE they can be fed to Argon2 (which would
        // otherwise attempt a multi-hundred-GiB allocation / unbounded compute
        // pre-authentication -- a memory/CPU DoS).
        let mut h = test_header();
        h.kdf.mem_kib = u32::MAX;
        assert!(matches!(
            VaultHeader::from_bytes(&h.to_bytes()),
            Err(crate::Error::Format(_))
        ));

        let mut h = test_header();
        h.kdf.time = u32::MAX;
        assert!(matches!(
            VaultHeader::from_bytes(&h.to_bytes()),
            Err(crate::Error::Format(_))
        ));

        // A normal, default-tuned parameter set still parses fine.
        let mut h = test_header();
        h.kdf = Argon2Params::default_tuned();
        assert!(VaultHeader::from_bytes(&h.to_bytes()).is_ok());
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
        // A successful unlock already proves the header MAC (unlock fails closed on
        // mismatch). Tombstone padding is filtered from the logical record view.
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
    fn save_aborts_if_vault_changed_on_disk_since_load() {
        // F6: optimistic concurrency. A vault loaded from disk records a
        // fingerprint of what it read; if another writer changes the file before
        // we save, `save` must refuse rather than silently clobber that change.
        let dek = SecretBytes::from_exact(&[11u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("email", SecretString::from_string("v1".into())).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("vaultcore_test_optconc_{}.ztsv", std::process::id()));
        v.save(&path).unwrap();

        // Reopen from disk (captures the on-disk fingerprint).
        let loaded = LockedVault::load(&path).unwrap();
        let dek2 = SecretBytes::from_exact(&[11u8; 32]);
        let mut reopened = loaded.unlock_with_dek(dek2).unwrap();

        // A concurrent writer changes the file underneath us.
        std::fs::write(&path, b"a concurrent writer got here first").unwrap();

        // Our save must fail closed instead of overwriting that change.
        reopened.add("bank", SecretString::from_string("v2".into())).unwrap();
        let res = reopened.save(&path);
        std::fs::remove_file(&path).ok();
        assert!(res.is_err(), "save must abort when the file changed since load");
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
        // Successful unlock proves the MAC; tombstones are filtered from the view.
        assert_eq!(unlocked.records().len(), 2);
        assert_eq!(unlocked.get("email").unwrap().expose_str(), "hunter2");
        assert_eq!(unlocked.get("bank_pin").unwrap().expose_str(), "1234");
    }

    // --- v3 metadata-encryption properties ---

    #[test]
    fn record_names_are_encrypted_on_disk() {
        let dek = SecretBytes::from_exact(&[12u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("my-secret-account-name", SecretString::from_string("hunter2".into())).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("vaultcore_v3_names_{}.ztsv", std::process::id()));
        v.save(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).ok();

        // Neither the name nor the value may appear in cleartext anywhere in the file.
        assert!(
            !contains(&bytes, b"my-secret-account-name"),
            "record name must not be plaintext on disk"
        );
        assert!(!contains(&bytes, b"hunter2"), "value must not be plaintext on disk");
    }

    #[test]
    fn count_is_padded_with_tombstones_and_filtered_on_unlock() {
        let dek = SecretBytes::from_exact(&[13u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("only-one", SecretString::from_string("x".into())).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("vaultcore_v3_count_{}.ztsv", std::process::id()));
        v.save(&path).unwrap();

        let locked = LockedVault::load(&path).unwrap();
        // On disk: padded up to a multiple of COUNT_BUCKET (>= COUNT_BUCKET).
        assert_eq!(locked.raw_record_count(), COUNT_BUCKET);
        assert!(locked.raw_record_count() % COUNT_BUCKET == 0);

        let unlocked = locked.unlock_with_dek(SecretBytes::from_exact(&[13u8; 32])).unwrap();
        // Logical view drops tombstones: exactly the one real record.
        assert_eq!(unlocked.records().len(), 1);
        assert_eq!(unlocked.get("only-one").unwrap().expose_str(), "x");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_vault_is_all_tombstones() {
        let dek = SecretBytes::from_exact(&[14u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        let mut path = std::env::temp_dir();
        path.push(format!("vaultcore_v3_empty_{}.ztsv", std::process::id()));
        v.save(&path).unwrap();
        let locked = LockedVault::load(&path).unwrap();
        assert_eq!(locked.raw_record_count(), COUNT_BUCKET);
        let unlocked = locked.unlock_with_dek(SecretBytes::from_exact(&[14u8; 32])).unwrap();
        assert_eq!(unlocked.records().len(), 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn short_values_share_a_size_bucket() {
        // Two different-length short values must produce equal-length value
        // ciphertexts (same VALUE_BUCKET), so a stolen file leaks no size info.
        let dek = SecretBytes::from_exact(&[15u8; 32]);
        let mut v = Vault::new_unlocked(dek, test_header());
        v.add("a", SecretString::from_string("x".into())).unwrap();
        v.add("b", SecretString::from_string("a-much-longer-but-still-sub-bucket-value".into()))
            .unwrap();
        let lens: Vec<usize> = v.records().iter().map(|r| r.value_ct.len()).collect();
        assert_eq!(lens[0], lens[1], "sub-bucket values must have equal ciphertext length");
    }

    /// Substring search used by the on-disk-secrecy tests.
    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }
}
