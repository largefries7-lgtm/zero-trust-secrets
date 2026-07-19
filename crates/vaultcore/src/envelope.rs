//! Two-factor DEK envelope (format v2).
//!
//! The 256-bit DEK that encrypts records is wrapped under a key-encryption key
//! (KEK) derived from the available factors:
//!
//!   KEK = HKDF( [tpm_secret ‖] Argon2id(passphrase) )
//!
//! For a hardware-bound vault both factors are required, so neither the TPM
//! (which a same-user process can silently drive) nor the passphrase alone
//! recovers the DEK. For a `--allow-no-tpm` vault there is no TPM factor and the
//! passphrase is the sole factor.
//!
//! An OPTIONAL, off-by-default recovery escrow additionally wraps the DEK under a
//! *separate* recovery passphrase alone (single factor) so the vault survives TPM
//! loss — at the cost of reducing a stolen vault's security to that passphrase's
//! strength. Callers must surface that trade-off to the user.

use crate::crypto::{self, Argon2Params};
use crate::secret::{SecretBytes, SecretString};
use crate::Result;

/// AAD binding the primary (two-factor) DEK wrap to its purpose + format version.
const DEK_WRAP_AAD: &[u8] = b"ztsv-dek-wrap-v2";
/// AAD binding the single-factor recovery wrap to its purpose + format version.
const RECOVERY_WRAP_AAD: &[u8] = b"ztsv-recovery-wrap-v2";

/// Wrap the DEK under the two-factor KEK. `tpm_secret = Some` ⇒ hardware-bound.
pub fn wrap_dek(
    dek: &SecretBytes,
    passphrase: &SecretString,
    kdf: &Argon2Params,
    tpm_secret: Option<&SecretBytes>,
) -> Result<Vec<u8>> {
    let pass_key = crypto::derive_kek(passphrase, kdf)?;
    let kek = crypto::derive_kek_v2(&pass_key, tpm_secret);
    crypto::aead_seal(&kek, DEK_WRAP_AAD, dek.expose())
}

/// Recover the DEK from the primary wrap. Requires the same factor set used to
/// wrap it: fails closed (`Error::AuthFailed`) on a wrong passphrase or wrong/
/// missing TPM secret.
pub fn unwrap_dek(
    dek_wrap: &[u8],
    passphrase: &SecretString,
    kdf: &Argon2Params,
    tpm_secret: Option<&SecretBytes>,
) -> Result<SecretBytes> {
    let pass_key = crypto::derive_kek(passphrase, kdf)?;
    let kek = crypto::derive_kek_v2(&pass_key, tpm_secret);
    crypto::aead_open(&kek, DEK_WRAP_AAD, dek_wrap)
}

/// Wrap the DEK under a single-factor recovery KEK (recovery passphrase only).
pub fn wrap_dek_recovery(
    dek: &SecretBytes,
    recovery_pass: &SecretString,
    kdf: &Argon2Params,
) -> Result<Vec<u8>> {
    let rec_key = crypto::derive_kek(recovery_pass, kdf)?;
    crypto::aead_seal(&rec_key, RECOVERY_WRAP_AAD, dek.expose())
}

/// Recover the DEK from the recovery wrap (recovery passphrase only). Fails
/// closed on a wrong passphrase.
pub fn unwrap_dek_recovery(
    recovery_wrap: &[u8],
    recovery_pass: &SecretString,
    kdf: &Argon2Params,
) -> Result<SecretBytes> {
    let rec_key = crypto::derive_kek(recovery_pass, kdf)?;
    crypto::aead_open(&rec_key, RECOVERY_WRAP_AAD, recovery_wrap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(salt: u8) -> Argon2Params {
        Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [salt; 16] }
    }

    #[test]
    fn two_factor_roundtrip_and_wrong_factor_fails() {
        let dek = SecretBytes::from_exact(&[42u8; 32]);
        let pass = SecretString::from_string("unlock-pw".into());
        let tpm = SecretBytes::from_exact(&[7u8; 32]);
        let kdf = params(1);

        let wrap = wrap_dek(&dek, &pass, &kdf, Some(&tpm)).unwrap();

        // Correct passphrase + correct TPM secret -> recovers the DEK.
        let out = unwrap_dek(&wrap, &pass, &kdf, Some(&tpm)).unwrap();
        assert!(dek.ct_eq(&out));

        // Passphrase alone (no TPM factor) -> AuthFailed.
        assert!(unwrap_dek(&wrap, &pass, &kdf, None).is_err());
        // Wrong TPM secret -> AuthFailed.
        assert!(unwrap_dek(&wrap, &pass, &kdf, Some(&SecretBytes::from_exact(&[8u8; 32]))).is_err());
        // Wrong passphrase -> AuthFailed.
        let wrong = SecretString::from_string("nope".into());
        assert!(unwrap_dek(&wrap, &wrong, &kdf, Some(&tpm)).is_err());
    }

    #[test]
    fn no_tpm_single_factor_roundtrip() {
        let dek = SecretBytes::from_exact(&[3u8; 32]);
        let pass = SecretString::from_string("only-pw".into());
        let kdf = params(2);
        let wrap = wrap_dek(&dek, &pass, &kdf, None).unwrap();
        assert!(dek.ct_eq(&unwrap_dek(&wrap, &pass, &kdf, None).unwrap()));
        // A wrap made without the TPM factor must NOT open if a TPM factor is
        // (incorrectly) supplied.
        assert!(unwrap_dek(&wrap, &pass, &kdf, Some(&SecretBytes::from_exact(&[1u8; 32]))).is_err());
    }

    #[test]
    fn recovery_roundtrip_and_wrong_passphrase_fails() {
        let dek = SecretBytes::from_exact(&[5u8; 32]);
        let rec = SecretString::from_string("recovery-pw".into());
        let kdf = params(9);
        let wrap = wrap_dek_recovery(&dek, &rec, &kdf).unwrap();
        assert!(dek.ct_eq(&unwrap_dek_recovery(&wrap, &rec, &kdf).unwrap()));
        let wrong = SecretString::from_string("bad".into());
        assert!(unwrap_dek_recovery(&wrap, &wrong, &kdf).is_err());
    }

    #[test]
    fn primary_and_recovery_aads_are_distinct() {
        // A recovery wrap must not open as a primary wrap or vice-versa, even
        // with the same key material, thanks to distinct AADs.
        let dek = SecretBytes::from_exact(&[6u8; 32]);
        let pass = SecretString::from_string("same".into());
        let kdf = params(DEK_WRAP_AAD[0]);
        // Single-factor primary (no tpm) uses HKDF(pass_key); recovery uses
        // pass_key directly with a different AAD — cross-open must fail.
        let prim = wrap_dek(&dek, &pass, &kdf, None).unwrap();
        assert!(unwrap_dek_recovery(&prim, &pass, &kdf).is_err());
        let recv = wrap_dek_recovery(&dek, &pass, &kdf).unwrap();
        assert!(unwrap_dek(&recv, &pass, &kdf, None).is_err());
    }
}
