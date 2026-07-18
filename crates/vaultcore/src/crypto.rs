use crate::secret::{SecretBytes, SecretString};
use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::time::{Duration, Instant};

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

/// Derive the key-encryption key (KEK) that wraps the DEK, from the available
/// factors, for the two-factor (v2) envelope.
///
/// `pass_key` is the Argon2id output of the unlock passphrase. `tpm_secret`, when
/// present (a hardware-bound vault), is the 32-byte secret unsealed from the TPM.
/// When the TPM factor is present the KEK depends on BOTH inputs, so neither the
/// TPM alone (which same-user malware can drive) nor the passphrase alone yields
/// the KEK. The inputs are fixed-length (32 bytes each), so their concatenation
/// as HKDF IKM is unambiguous; a distinct `info` label domain-separates this KEK.
pub fn derive_kek_v2(pass_key: &SecretBytes, tpm_secret: Option<&SecretBytes>) -> SecretBytes {
    use zeroize::Zeroize;
    let mut ikm = Vec::with_capacity(2 * KEY_LEN);
    if let Some(ts) = tpm_secret {
        ikm.extend_from_slice(ts.expose());
    }
    ikm.extend_from_slice(pass_key.expose());
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = SecretBytes::zeros(KEY_LEN);
    hk.expand(b"ztsv-kek-v2", out.expose_mut())
        .expect("hkdf out_len == 32 <= 255*32");
    ikm.zeroize(); // scrub the transient concatenation of secret factors
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
    /// Calibration floor: never produce a vault weaker than 256 MiB of Argon2
    /// memory, even on a slow machine where that already exceeds the time target.
    pub const CAL_FLOOR_MEM_KIB: u32 = 256 * 1024;
    /// Calibration cap: 1 GiB, matching `vault::MAX_ARGON2_MEM_KIB` so a calibrated
    /// header always parses. Memory is the honest Argon2 cost knob here.
    pub const CAL_CAP_MEM_KIB: u32 = 1 << 20;
    /// Time cost held fixed during calibration (memory is varied instead).
    pub const CAL_TIME: u32 = 3;
    /// Parallelism held at 1: the RustCrypto `argon2` crate computes lanes
    /// serially, so raising `p` changes the memory layout without buying wall-clock
    /// hardness. Keeping it 1 makes the cost model honest.
    pub const CAL_PARALLELISM: u32 = 1;

    /// The calibration cap must equal the vault parser's accepted maximum, or a
    /// calibrated header could fail to load. Enforced at compile time.
    const _CAP_MATCHES_PARSER: () =
        assert!(Self::CAL_CAP_MEM_KIB == crate::vault::MAX_ARGON2_MEM_KIB);

    pub fn default_tuned() -> Self {
        Self { mem_kib: 65536, time: 3, parallelism: 1, salt: Self::random_salt() }
    }
    pub fn random_salt() -> [u8; 16] {
        let mut s = [0u8; 16];
        OsRng.fill_bytes(&mut s);
        s
    }

    /// Auto-calibrate at vault creation: pick the LARGEST Argon2 memory (within
    /// [`CAL_FLOOR_MEM_KIB`, `CAL_CAP_MEM_KIB`]) whose single derivation stays at
    /// or under `target`, but never below the floor. `max_trial` bounds any one
    /// probe so a pathologically slow machine cannot hang `init`. Returns params
    /// with a FRESH random salt.
    pub fn calibrate(target: Duration, max_trial: Duration) -> Self {
        Self::calibrate_with(
            Self::CAL_FLOOR_MEM_KIB,
            Self::CAL_CAP_MEM_KIB,
            Self::CAL_TIME,
            Self::CAL_PARALLELISM,
            target,
            max_trial,
        )
    }

    /// Calibration core, parameterized so tests can exercise the climbing logic
    /// with tiny (fast) floor/cap values instead of hundreds of MiB.
    fn calibrate_with(
        floor: u32,
        cap: u32,
        time: u32,
        parallelism: u32,
        target: Duration,
        max_trial: Duration,
    ) -> Self {
        let mut chosen = floor;
        let mut mem = floor;
        loop {
            let dt = Self::probe(mem, time, parallelism);
            // Accept this level if it's under the time budget; then try bigger.
            // The floor is accepted unconditionally (security floor beats the
            // latency target on a weak machine).
            if mem == floor || dt <= target {
                chosen = mem;
            } else {
                break; // this level is too slow; keep the previous `chosen`
            }
            if mem >= cap || dt > max_trial {
                break;
            }
            let next = mem.saturating_mul(2).min(cap);
            if next == mem {
                break;
            }
            mem = next;
        }
        Self { mem_kib: chosen, time, parallelism, salt: Self::random_salt() }
    }

    /// Time a single Argon2 derivation at the given cost. Errors (which should not
    /// occur for in-range params) are treated as "over target" so calibration
    /// backs off rather than selecting a broken level.
    fn probe(mem_kib: u32, time: u32, parallelism: u32) -> Duration {
        let params = Argon2Params { mem_kib, time, parallelism, salt: [0u8; 16] };
        let probe_pw = SecretString::from_string("ztsv-calibration-probe".to_string());
        let start = Instant::now();
        let ok = derive_kek(&probe_pw, &params).is_ok();
        let elapsed = start.elapsed();
        if ok {
            elapsed
        } else {
            Duration::from_secs(u64::MAX / 2)
        }
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
    fn kek_v2_requires_both_factors_and_is_deterministic() {
        let pass = SecretBytes::from_exact(&[1u8; KEY_LEN]);
        let tpm = SecretBytes::from_exact(&[2u8; KEY_LEN]);

        let both = derive_kek_v2(&pass, Some(&tpm));
        // Deterministic for the same factors.
        assert!(both.ct_eq(&derive_kek_v2(&pass, Some(&tpm))));
        // Passphrase alone (no TPM factor) yields a DIFFERENT KEK: a same-user
        // attacker who can drive the TPM but lacks the passphrase cannot get it,
        // and vice-versa.
        assert!(!both.ct_eq(&derive_kek_v2(&pass, None)));
        // Wrong TPM secret -> different KEK.
        assert!(!both.ct_eq(&derive_kek_v2(&pass, Some(&SecretBytes::from_exact(&[9u8; KEY_LEN])))));
        // Wrong passphrase -> different KEK.
        let pass2 = SecretBytes::from_exact(&[7u8; KEY_LEN]);
        assert!(!both.ct_eq(&derive_kek_v2(&pass2, Some(&tpm))));
        assert_eq!(both.len(), KEY_LEN);
    }

    #[test]
    fn derive_kek_is_stable_for_same_input() {
        let p = Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [1u8; 16] };
        let k1 = derive_kek(&SecretString::from_string("pw".into()), &p).unwrap();
        let k2 = derive_kek(&SecretString::from_string("pw".into()), &p).unwrap();
        assert!(k1.ct_eq(&k2));
        assert_eq!(k1.len(), KEY_LEN);
    }

    #[test]
    fn calibration_climbs_with_a_generous_budget() {
        // Tiny floor/cap so the test is fast. A large time budget means every
        // level is "under target", so calibration should climb all the way to the
        // cap and stop there.
        let p = Argon2Params::calibrate_with(
            8,
            64,
            1,
            1,
            Duration::from_secs(10),
            Duration::from_secs(10),
        );
        assert_eq!(p.mem_kib, 64, "should climb to the cap under a generous budget");
        assert_eq!(p.time, 1);
        assert_eq!(p.parallelism, 1);
    }

    #[test]
    fn calibration_respects_the_floor_under_a_zero_budget() {
        // A near-zero target means even the floor level exceeds it, so calibration
        // must still return the floor (security floor beats the latency target),
        // never something weaker, and never climb.
        let p = Argon2Params::calibrate_with(
            8,
            64,
            1,
            1,
            Duration::from_nanos(1),
            Duration::from_secs(10),
        );
        assert_eq!(p.mem_kib, 8, "floor is used even when it exceeds the time target");
    }

    #[test]
    fn production_calibrate_stays_within_bounds() {
        // The real calibration must always land within [floor, cap] regardless of
        // machine speed. Use a near-zero target so it stops at the floor quickly
        // (one probe) rather than climbing to 1 GiB during the test.
        let p = Argon2Params::calibrate(Duration::from_nanos(1), Duration::from_secs(5));
        assert!(p.mem_kib >= Argon2Params::CAL_FLOOR_MEM_KIB);
        assert!(p.mem_kib <= Argon2Params::CAL_CAP_MEM_KIB);
        assert_eq!(p.time, Argon2Params::CAL_TIME);
        // A calibrated header must be within the vault parser's accepted range
        // (the cap equality is also enforced at compile time above).
        assert!(p.mem_kib <= Argon2Params::CAL_CAP_MEM_KIB);
    }
}
