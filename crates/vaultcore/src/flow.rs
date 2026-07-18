//! Create/unlock orchestration, lifted out of `vaultctl` so the CLI and GUI drive
//! identical, tested flows. This composes existing vaultcore pieces (the TPM
//! provider, the two-factor envelope, the vault codec) — it introduces NO new
//! cryptography. Callers own all user-facing messaging; these functions are silent.

use crate::crypto::Argon2Params;
use crate::envelope;
use crate::recovery::RecoveryCode;
use crate::secret::{SecretBytes, SecretString};
use crate::strength::{self, Policy};
use crate::vault::{LockedVault, Vault, VaultHeader};
use crate::{Error, Result};
use std::path::Path;
use std::time::Duration;

/// Target unlock latency the KDF auto-calibration aims for at vault creation.
const KDF_CALIBRATION_TARGET: Duration = Duration::from_millis(750);
/// Per-probe safety bound so calibration can't hang `init` on a very slow machine.
const KDF_CALIBRATION_MAX_TRIAL: Duration = Duration::from_secs(3);

/// How the Argon2id passphrase KDF cost is chosen for a new vault.
pub enum KdfStrategy {
    /// Auto-calibrate at creation to `KDF_CALIBRATION_TARGET` (floor 256 MiB, cap
    /// 1 GiB). This is what production callers use.
    Calibrate,
    /// Use exactly these parameters. For tests and advanced callers that must
    /// avoid the (deliberately expensive) calibration.
    Fixed(Argon2Params),
}

impl KdfStrategy {
    fn resolve(&self) -> Argon2Params {
        match self {
            KdfStrategy::Calibrate => {
                Argon2Params::calibrate(KDF_CALIBRATION_TARGET, KDF_CALIBRATION_MAX_TRIAL)
            }
            KdfStrategy::Fixed(p) => *p,
        }
    }
}

#[cfg(windows)]
use crate::keyprovider::{CngPcpProvider, KeyProvider, RecoveryProvider, SealedBlob};
// `KeyProvider` is needed here too (not only on Windows): `describe_provider`
// calls the trait method `RecoveryProvider::describe`, so the trait must be in
// scope on every target. Without it, non-Windows builds fail E0599 (the Windows
// import above masked this because it already pulls `KeyProvider` in).
#[cfg(not(windows))]
use crate::keyprovider::{KeyProvider, RecoveryProvider};

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
    /// Opt in to a single-factor recovery escrow. When set, `create_vault`
    /// generates a 128-bit recovery CODE (not a human passphrase) and returns it
    /// once in `CreateOutcome::recovery_code`.
    pub recovery: bool,
    /// How to choose the Argon2id cost. Production uses `Calibrate`.
    pub kdf: KdfStrategy,
}

pub struct CreateOutcome {
    pub hardware_bound: bool,
    pub has_recovery: bool,
    pub tpm: TpmBinding,
    /// The generated recovery code in its human-facing grouped form, present iff
    /// `recovery` was requested. Shown to the user ONCE and never stored; the
    /// caller must display it and then let it drop.
    pub recovery_code: Option<String>,
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

        // Acquire the TPM factor FIRST so we know whether the vault will be
        // hardware-bound, which selects the passphrase-strength policy: a
        // single-factor (no-TPM) vault must clear a higher floor than a
        // two-factor one, because the passphrase is then the ONLY thing between a
        // stolen file and the secrets.
        let (tpm_wrap, tpm_secret, tpm) = acquire_tpm_factor(opts.allow_no_tpm);
        let hardware_bound = matches!(tpm, TpmBinding::Bound);

        let policy = if hardware_bound { Policy::two_factor() } else { Policy::single_factor() };
        strength::check(opts.passphrase.expose_str(), &policy)
            .map_err(|w| Error::WeakPassphrase(w.to_string()))?;

        // Auto-calibrated (or fixed, for tests) Argon2id cost.
        let kdf = opts.kdf.resolve();

        let dek_wrap = envelope::wrap_dek(&dek, &opts.passphrase, &kdf, tpm_secret.as_ref())?;

        // Optional recovery escrow: a generated 128-bit code, not a human
        // passphrase. Reuse the primary KDF's cost with a fresh salt (the code is
        // already 128-bit, so the KDF here is defense-in-depth) to avoid a second
        // expensive calibration pass.
        let (recovery_pair, recovery_code) = if opts.recovery {
            let code = RecoveryCode::generate();
            let rkdf = Argon2Params { salt: Argon2Params::random_salt(), ..kdf };
            let rw = envelope::wrap_dek_recovery(&dek, code.secret(), &rkdf)?;
            (Some((rw, rkdf)), Some(code.display()))
        } else {
            (None, None)
        };
        let has_recovery = recovery_pair.is_some();

        let header = VaultHeader::new_v2(hardware_bound, kdf, tpm_wrap, dek_wrap, recovery_pair);
        let mut vault = Vault::new_unlocked(dek, header);
        vault.save(path)?;

        Ok(CreateOutcome { hardware_bound, has_recovery, tpm, recovery_code })
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

/// Unlock via the recovery escrow using the human-entered recovery CODE. The input
/// is normalized (case, dashes and spacing tolerated; ambiguous O/I/L corrected)
/// before deriving, so it matches however the user transcribed it. Fails closed on
/// a wrong code or a vault with no recovery escrow. Both the CLI and GUI route
/// recovery unlock through here so normalization lives in exactly one place.
pub fn unlock_with_recovery_code(locked: LockedVault, code_input: &str) -> Result<Vault> {
    let code = RecoveryCode::from_user_input(code_input);
    locked.unlock_recovery(code.secret())
}

/// Acquires the TPM secret factor for a hardware-bound vault (unseals via the
/// CNG provider); returns `Ok(None)` for a non-hardware-bound vault; fails
/// closed for a hardware-bound vault whose TPM factor is unavailable.
#[cfg(windows)]
pub fn obtain_tpm_secret(locked: &LockedVault) -> Result<Option<SecretBytes>> {
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

/// Acquires the TPM secret factor for a hardware-bound vault (unseals via the
/// CNG provider); returns `Ok(None)` for a non-hardware-bound vault; fails
/// closed for a hardware-bound vault whose TPM factor is unavailable.
#[cfg(not(windows))]
pub fn obtain_tpm_secret(locked: &LockedVault) -> Result<Option<SecretBytes>> {
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

    /// A passphrase comfortably above the single-factor floor (mixed classes, 22
    /// chars ≈ 140+ bits), so it clears the creation strength gate in tests.
    const STRONG: &str = "Gv7!kQ2m-Zp9x_Lw3r#Ht6";

    fn tmp(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("vaultcore_flow_{}_{}.ztsv", tag, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Cheap fixed KDF so tests don't pay the (deliberately expensive) production
    /// calibration.
    fn fast_kdf() -> KdfStrategy {
        KdfStrategy::Fixed(Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [7u8; 16] })
    }

    fn create_opts(recovery: bool) -> CreateOptions {
        CreateOptions {
            allow_no_tpm: true,
            passphrase: SecretString::from_string(STRONG.into()),
            recovery,
            kdf: fast_kdf(),
        }
    }

    #[test]
    fn create_no_tpm_then_unlock_roundtrip() {
        let path = tmp("roundtrip");
        let out = create_vault(&path, create_opts(false)).unwrap();
        assert!(!out.hardware_bound);
        assert!(!out.has_recovery);
        assert!(out.recovery_code.is_none());
        assert!(matches!(out.tpm, TpmBinding::OptedOut));

        let locked = LockedVault::load(&path).unwrap();
        let pass = SecretString::from_string(STRONG.into());
        let v = unlock(locked, UnlockFactors::TwoFactor { passphrase: &pass }).unwrap();
        assert!(v.is_unlocked());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn weak_passphrase_is_rejected_at_creation() {
        let path = tmp("weakpw");
        let out = create_vault(
            &path,
            CreateOptions {
                allow_no_tpm: true,
                passphrase: SecretString::from_string("password1".into()),
                recovery: false,
                kdf: fast_kdf(),
            },
        );
        assert!(matches!(out, Err(Error::WeakPassphrase(_))));
        // The placeholder file must be cleaned up so a retry isn't blocked.
        assert!(!path.exists(), "weak-passphrase failure must not leave a vault file");
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let path = tmp("wrongpw");
        create_vault(&path, create_opts(false)).unwrap();
        let locked = LockedVault::load(&path).unwrap();
        let wrong = SecretString::from_string("wrong-but-unchecked-on-unlock".into());
        assert!(unlock(locked, UnlockFactors::TwoFactor { passphrase: &wrong }).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn recovery_code_unlocks_and_create_refuses_clobber() {
        let path = tmp("recovery");
        let out = create_vault(&path, create_opts(true)).unwrap();
        assert!(out.has_recovery);
        let code = out.recovery_code.expect("recovery requested -> code returned");

        // create refuses to clobber an existing file
        assert!(create_vault(&path, create_opts(false)).is_err());

        // Unlock via the generated code (through the shared normalizing helper),
        // even with formatting noise the user might introduce.
        let noisy = format!(" {} ", code.to_lowercase());
        let locked = LockedVault::load(&path).unwrap();
        let v = unlock_with_recovery_code(locked, &noisy).unwrap();
        assert!(v.is_unlocked());

        // A wrong code fails closed.
        let locked = LockedVault::load(&path).unwrap();
        assert!(unlock_with_recovery_code(locked, "0000-0000-0000-0000-0000-0000-00").is_err());
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
        create_vault(&path, create_opts(false)).unwrap();
        let locked = LockedVault::load(&path).unwrap();
        let s = describe_provider(locked.header());
        assert!(s.contains("NO hardware binding"));
        assert!(!s.contains("Platform Crypto"));
        std::fs::remove_file(&path).ok();
    }
}
