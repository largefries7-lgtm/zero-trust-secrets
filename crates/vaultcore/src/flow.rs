//! Create/unlock orchestration, lifted out of `vaultctl` so the CLI and GUI drive
//! identical, tested flows. This composes existing vaultcore pieces (the TPM
//! provider, the two-factor envelope, the vault codec) — it introduces NO new
//! cryptography. Callers own all user-facing messaging; these functions are silent.

use crate::crypto::Argon2Params;
use crate::envelope;
use crate::secret::{SecretBytes, SecretString};
use crate::vault::{LockedVault, Vault, VaultHeader};
use crate::{Error, Result};
use std::path::Path;

#[cfg(windows)]
use crate::keyprovider::{CngPcpProvider, KeyProvider, RecoveryProvider, SealedBlob};
#[cfg(not(windows))]
use crate::keyprovider::RecoveryProvider;

/// Why a vault did (not) end up hardware-bound, so callers can warn precisely.
#[derive(Debug)]
pub enum TpmBinding {
    Bound,
    OptedOut,
    Unavailable(String),
    SealFailed(String),
}

pub struct CreateOptions {
    pub allow_no_tpm: bool,
    pub passphrase: SecretString,
    pub recovery_passphrase: Option<SecretString>,
}

pub struct CreateOutcome {
    pub hardware_bound: bool,
    pub has_recovery: bool,
    pub tpm: TpmBinding,
}

pub enum UnlockFactors<'a> {
    TwoFactor { passphrase: &'a SecretString },
    Recovery { recovery_passphrase: &'a SecretString },
}

/// Best-effort TPM secret factor. Returns (tpm_wrap, tpm_secret, binding).
#[cfg(windows)]
fn acquire_tpm_factor(allow_no_tpm: bool) -> (Option<Vec<u8>>, Option<SecretBytes>, TpmBinding) {
    if allow_no_tpm {
        return (None, None, TpmBinding::OptedOut);
    }
    match CngPcpProvider::open() {
        Ok(provider) => {
            let secret = SecretBytes::generate(32);
            match provider.seal(&secret, &[]) {
                Ok(blob) => (Some(blob.0), Some(secret), TpmBinding::Bound),
                Err(e) => (None, None, TpmBinding::SealFailed(e.to_string())),
            }
        }
        Err(e) => (None, None, TpmBinding::Unavailable(e.to_string())),
    }
}

#[cfg(not(windows))]
fn acquire_tpm_factor(allow_no_tpm: bool) -> (Option<Vec<u8>>, Option<SecretBytes>, TpmBinding) {
    if allow_no_tpm {
        (None, None, TpmBinding::OptedOut)
    } else {
        (None, None, TpmBinding::Unavailable("no TPM provider on this platform".into()))
    }
}

pub fn create_vault(path: &Path, opts: CreateOptions) -> Result<CreateOutcome> {
    // Atomically claim `path` before doing any slow work (KDF, TPM seal, wrap).
    // `create_new` is an atomic "create iff absent" at the OS level, so two
    // concurrent `create_vault` calls on the same path can no longer both pass
    // a `path.exists()` guard and then race to clobber each other via `save`'s
    // rename. The empty placeholder this creates is replaced by `Vault::save`'s
    // temp-then-rename on success; on any error below we remove it so a retry
    // isn't left permanently blocked by a leftover empty file.
    match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(f) => drop(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::Provider(format!(
                "vault already exists at {}; refusing to overwrite",
                path.display()
            )));
        }
        Err(e) => return Err(Error::Io(e)),
    }

    let result = (|| -> Result<CreateOutcome> {
        let dek = SecretBytes::generate(32);
        let kdf = Argon2Params::default_tuned();

        let (tpm_wrap, tpm_secret, tpm) = acquire_tpm_factor(opts.allow_no_tpm);
        let hardware_bound = matches!(tpm, TpmBinding::Bound);

        let dek_wrap = envelope::wrap_dek(&dek, &opts.passphrase, &kdf, tpm_secret.as_ref())?;

        let has_recovery = opts.recovery_passphrase.is_some();
        let recovery_pair = match &opts.recovery_passphrase {
            Some(rp) => {
                let rkdf = Argon2Params::default_tuned();
                let rw = envelope::wrap_dek_recovery(&dek, rp, &rkdf)?;
                Some((rw, rkdf))
            }
            None => None,
        };

        let header = VaultHeader::new_v2(hardware_bound, kdf, tpm_wrap, dek_wrap, recovery_pair);
        let mut vault = Vault::new_unlocked(dek, header);
        vault.save(path)?;

        Ok(CreateOutcome { hardware_bound, has_recovery, tpm })
    })();

    if result.is_err() {
        // Remove the empty placeholder so a retry after a failure isn't
        // blocked by our own `create_new` claim. `save` already replaced it
        // on the success path, so there is nothing to clean up there.
        let _ = std::fs::remove_file(path);
    }
    result
}

pub fn unlock(locked: LockedVault, factors: UnlockFactors) -> Result<Vault> {
    match factors {
        UnlockFactors::Recovery { recovery_passphrase } => locked.unlock_recovery(recovery_passphrase),
        UnlockFactors::TwoFactor { passphrase } => {
            let tpm_secret = obtain_tpm_secret(&locked)?;
            locked.unlock_two_factor(passphrase, tpm_secret.as_ref())
        }
    }
}

#[cfg(windows)]
fn obtain_tpm_secret(locked: &LockedVault) -> Result<Option<SecretBytes>> {
    if !locked.header().hardware_bound {
        return Ok(None);
    }
    let wrap = locked
        .header()
        .tpm_wrap
        .clone()
        .ok_or_else(|| Error::Provider("hardware_bound vault has no tpm_wrap".into()))?;
    let provider = CngPcpProvider::open()?;
    Ok(Some(provider.unseal(&SealedBlob(wrap))?))
}

#[cfg(not(windows))]
fn obtain_tpm_secret(locked: &LockedVault) -> Result<Option<SecretBytes>> {
    if locked.header().hardware_bound {
        return Err(Error::Provider("TPM path unavailable on this platform".into()));
    }
    Ok(None)
}

pub fn describe_provider(header: &VaultHeader) -> String {
    if header.hardware_bound {
        #[cfg(windows)]
        {
            if let Ok(provider) = CngPcpProvider::open() {
                return provider.describe();
            }
            return "TPM-backed (hardware_bound is set, but the CNG provider could not be opened)"
                .to_string();
        }
        #[cfg(not(windows))]
        {
            return "TPM-backed (hardware_bound is set, but this platform has no CNG provider)"
                .to_string();
        }
    }
    let recovery =
        RecoveryProvider::new(SecretString::from_string(String::new()), header.kdf).describe();
    format!("{recovery} — NO hardware binding")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("vaultcore_flow_{}_{}.ztsv", tag, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn create_no_tpm_then_unlock_roundtrip() {
        let path = tmp("roundtrip");
        let out = create_vault(
            &path,
            CreateOptions {
                allow_no_tpm: true,
                passphrase: SecretString::from_string("pw".into()),
                recovery_passphrase: None,
            },
        )
        .unwrap();
        assert!(!out.hardware_bound);
        assert!(!out.has_recovery);
        assert!(matches!(out.tpm, TpmBinding::OptedOut));

        let locked = LockedVault::load(&path).unwrap();
        let pass = SecretString::from_string("pw".into());
        let v = unlock(locked, UnlockFactors::TwoFactor { passphrase: &pass }).unwrap();
        assert!(v.is_unlocked());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let path = tmp("wrongpw");
        create_vault(
            &path,
            CreateOptions {
                allow_no_tpm: true,
                passphrase: SecretString::from_string("right".into()),
                recovery_passphrase: None,
            },
        )
        .unwrap();
        let locked = LockedVault::load(&path).unwrap();
        let wrong = SecretString::from_string("wrong".into());
        assert!(unlock(locked, UnlockFactors::TwoFactor { passphrase: &wrong }).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn recovery_escrow_unlocks_and_create_refuses_clobber() {
        let path = tmp("recovery");
        let out = create_vault(
            &path,
            CreateOptions {
                allow_no_tpm: true,
                passphrase: SecretString::from_string("unlockpw".into()),
                recovery_passphrase: Some(SecretString::from_string("recpw".into())),
            },
        )
        .unwrap();
        assert!(out.has_recovery);

        // create refuses to clobber an existing file
        assert!(create_vault(
            &path,
            CreateOptions {
                allow_no_tpm: true,
                passphrase: SecretString::from_string("x".into()),
                recovery_passphrase: None,
            },
        )
        .is_err());

        let locked = LockedVault::load(&path).unwrap();
        let rec = SecretString::from_string("recpw".into());
        let v = unlock(locked, UnlockFactors::Recovery { recovery_passphrase: &rec }).unwrap();
        assert!(v.is_unlocked());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn hardware_bound_unlock_fails_closed_without_valid_tpm_factor() {
        let path = tmp("hwfailclosed");
        // A hardware-bound header with a BOGUS tpm_wrap. On non-Windows, obtain_tpm_secret
        // errors immediately; on Windows, unsealing the bogus wrap fails -- either way unlock
        // must fail closed BEFORE reaching the DEK unwrap.
        let dek = SecretBytes::generate(32);
        let header = VaultHeader::new_v2(
            true,
            Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [3u8; 16] },
            Some(vec![0u8; 32]),
            vec![0u8; 16],
            None,
        );
        let mut v = Vault::new_unlocked(dek, header);
        v.save(&path).unwrap();

        let locked = LockedVault::load(&path).unwrap();
        let pass = SecretString::from_string("pw".into());
        assert!(unlock(locked, UnlockFactors::TwoFactor { passphrase: &pass }).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn describe_provider_is_honest_for_no_hardware() {
        let path = tmp("describe");
        create_vault(
            &path,
            CreateOptions {
                allow_no_tpm: true,
                passphrase: SecretString::from_string("pw".into()),
                recovery_passphrase: None,
            },
        )
        .unwrap();
        let locked = LockedVault::load(&path).unwrap();
        let s = describe_provider(locked.header());
        assert!(s.contains("NO hardware binding"));
        assert!(!s.contains("Platform Crypto"));
        std::fs::remove_file(&path).ok();
    }
}
