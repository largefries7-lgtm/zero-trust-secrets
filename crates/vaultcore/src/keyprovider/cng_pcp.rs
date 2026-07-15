//! Windows CNG Platform Crypto Provider (TPM-backed) key provider.
//!
//! Hardware-binds the vault DEK by wrapping it with a non-exportable, TPM-resident
//! RSA-2048 key held by the "Microsoft Platform Crypto Provider". `seal` performs an
//! RSA-OAEP(SHA-256) public-key encryption of the 32-byte DEK; `unseal` performs the
//! private-key decryption, which never leaves the TPM.
//!
//! Honesty note: CNG does not expose PCR-policy sealing at this granularity, so the DEK
//! is bound to the *platform key* (device-bound) but NOT to a specific PCR/boot state.
//! This is reflected by [`ProviderStatus::Degraded`] and by [`CngPcpProvider::describe`].

use super::{KeyProvider, ProviderStatus, SealedBlob};
use crate::secret::SecretBytes;
use crate::{Error, Result};

use core::ffi::c_void;
use core::ptr;
use zeroize::Zeroize;

use windows::Win32::Foundation::NTE_EXISTS;
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC,
    MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY,
    NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE,
};

/// Name of the persisted TPM-resident wrapping key.
const KEY_NAME: windows::core::PCWSTR = windows::core::w!("ZeroTrustSecretsDEKWrap");

/// RSA-2048 wrapping key. RSA-OAEP(SHA-256) leaves ample room for a 32-byte DEK.
const RSA_KEY_BITS: u32 = 2048;

/// TPM-backed key provider using the Windows CNG Platform Crypto Provider.
pub struct CngPcpProvider {
    prov: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
}

impl CngPcpProvider {
    /// Open the platform crypto provider and open-or-create the persisted, non-exportable
    /// RSA-2048 wrapping key. Returns `Err` if no usable platform TPM is present, so callers
    /// (and the availability-gated test) can skip cleanly.
    pub fn open() -> Result<Self> {
        let mut prov = NCRYPT_PROV_HANDLE::default();
        // SAFETY: `prov` is a valid, exclusively-borrowed out-pointer; `MS_PLATFORM_CRYPTO_PROVIDER`
        // is a 'static NUL-terminated wide string; flags are 0. The call only writes `*prov`.
        unsafe { NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) }
            .map_err(|e| prov_err("NCryptOpenStorageProvider", &e))?;

        match Self::acquire_key(prov) {
            Ok(key) => Ok(Self { prov, key }),
            Err(e) => {
                // Free the provider we just opened so it does not leak on the error path.
                // SAFETY: `prov` is a live provider handle from the successful open above and
                // has not been freed elsewhere.
                unsafe {
                    let _ = NCryptFreeObject(prov);
                }
                Err(e)
            }
        }
    }

    /// Open the existing persisted wrapping key, or create+finalize it if absent.
    fn acquire_key(prov: NCRYPT_PROV_HANDLE) -> Result<NCRYPT_KEY_HANDLE> {
        // Fast path: open an already-provisioned key.
        if let Some(key) = Self::try_open_key(prov) {
            return Ok(key);
        }

        // Create a fresh persisted RSA key.
        let mut key = NCRYPT_KEY_HANDLE::default();
        // SAFETY: `prov` is live; `key` is a valid out-pointer; `BCRYPT_RSA_ALGORITHM` and
        // `KEY_NAME` are 'static wide strings; key-spec and flags are 0.
        let create = unsafe {
            NCryptCreatePersistedKey(
                prov,
                &mut key,
                BCRYPT_RSA_ALGORITHM,
                KEY_NAME,
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        };
        if let Err(e) = create {
            // Lost a creation race: the key now exists, so just open it.
            if e.code() == NTE_EXISTS {
                return Self::try_open_key(prov)
                    .ok_or_else(|| Error::Provider("wrapping key exists but cannot be opened".into()));
            }
            return Err(prov_err("NCryptCreatePersistedKey", &e));
        }

        // Set RSA-2048 length before finalizing.
        let bits = RSA_KEY_BITS.to_le_bytes();
        // SAFETY: `key` is a freshly created, not-yet-finalized handle; `NCRYPT_LENGTH_PROPERTY`
        // is a 'static wide string; `bits` is a live 4-byte slice; flags are 0.
        if let Err(e) = unsafe { NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, &bits, NCRYPT_FLAGS(0)) }
        {
            // SAFETY: `key` is the live handle created just above.
            unsafe {
                let _ = NCryptFreeObject(key);
            }
            return Err(prov_err("NCryptSetProperty(Length)", &e));
        }

        // SAFETY: `key` is a live, not-yet-finalized handle; flags are 0.
        if let Err(e) = unsafe { NCryptFinalizeKey(key, NCRYPT_FLAGS(0)) } {
            // SAFETY: `key` is the live handle created just above.
            unsafe {
                let _ = NCryptFreeObject(key);
            }
            return Err(prov_err("NCryptFinalizeKey", &e));
        }

        Ok(key)
    }

    /// Delete the persisted TPM wrapping key from the platform key store.
    ///
    /// DESTRUCTIVE: every vault whose `tpm_wrap` was produced by this key becomes
    /// undecryptable via the TPM afterwards (a vault's recovery passphrase, if
    /// set, still works). Returns `Ok(true)` if a key was deleted, `Ok(false)` if
    /// none was present (idempotent). A subsequent `open()`/`init` recreates a
    /// FRESH keypair under the same name — it does not resurrect the old one.
    pub fn deprovision() -> Result<bool> {
        let mut prov = NCRYPT_PROV_HANDLE::default();
        // SAFETY: `prov` is a valid out-pointer; provider name is a 'static wide
        // string; flags are 0. Only `*prov` is written.
        unsafe { NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) }
            .map_err(|e| prov_err("NCryptOpenStorageProvider", &e))?;

        let deleted = match Self::try_open_key(prov) {
            Some(key) => {
                // SAFETY: `key` is a live handle just opened by try_open_key.
                // NCryptDeleteKey deletes the persisted key AND frees the handle,
                // so we must NOT call NCryptFreeObject on `key` afterwards.
                match unsafe { NCryptDeleteKey(key, 0) } {
                    Ok(()) => true,
                    Err(e) => {
                        // On failure the handle may still be live; free it.
                        // SAFETY: `key` is the live handle from try_open_key.
                        unsafe {
                            let _ = NCryptFreeObject(key);
                        }
                        // SAFETY: `prov` is the live provider handle from above.
                        unsafe {
                            let _ = NCryptFreeObject(prov);
                        }
                        return Err(prov_err("NCryptDeleteKey", &e));
                    }
                }
            }
            None => false,
        };

        // SAFETY: `prov` is the live provider handle from open; freed exactly once.
        unsafe {
            let _ = NCryptFreeObject(prov);
        }
        Ok(deleted)
    }

    /// Try to open the persisted key; `None` on any failure (e.g. not-found).
    fn try_open_key(prov: NCRYPT_PROV_HANDLE) -> Option<NCRYPT_KEY_HANDLE> {
        let mut key = NCRYPT_KEY_HANDLE::default();
        // SAFETY: `prov` is live; `key` is a valid out-pointer; `KEY_NAME` is a 'static wide
        // string; key-spec and flags are 0. On error nothing is written to `key`.
        let r = unsafe { NCryptOpenKey(prov, &mut key, KEY_NAME, CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)) };
        r.ok().map(|_| key)
    }
}

/// Fresh OAEP(SHA-256) padding descriptor with no label.
fn oaep_padding() -> BCRYPT_OAEP_PADDING_INFO {
    BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: ptr::null_mut(),
        cbLabel: 0,
    }
}

/// Map a Win32/NCrypt failure to `Error::Provider`, preserving the HRESULT.
fn prov_err(what: &str, e: &windows::core::Error) -> Error {
    Error::Provider(format!(
        "{what} failed (HRESULT {:#010X}): {e}",
        e.code().0 as u32
    ))
}

impl KeyProvider for CngPcpProvider {
    fn status(&self) -> ProviderStatus {
        // Honest status: CNG cannot express PCR-policy sealing, so the DEK is bound to the
        // non-exportable platform key (device-bound) but not to a boot/PCR state.
        ProviderStatus::Degraded(
            "PCR-policy sealing not available via CNG; DEK bound to non-exportable TPM platform key"
                .into(),
        )
    }

    fn seal(&self, dek: &SecretBytes, _pcrs: &[u32]) -> Result<SealedBlob> {
        let padding = oaep_padding();
        let padding_ptr = &padding as *const BCRYPT_OAEP_PADDING_INFO as *const c_void;
        let input = dek.expose();

        // First call: query the required ciphertext size.
        let mut needed: u32 = 0;
        // SAFETY: `self.key` is a live finalized key; `input` is a live slice; `padding_ptr`
        // points to the live `padding` value; output is `None` (size query); `needed` is a
        // valid out-pointer.
        unsafe {
            NCryptEncrypt(
                self.key,
                Some(input),
                Some(padding_ptr),
                None,
                &mut needed,
                NCRYPT_PAD_OAEP_FLAG,
            )
        }
        .map_err(|e| prov_err("NCryptEncrypt(size)", &e))?;

        // Second call: encrypt into an exactly-sized buffer.
        let mut out = vec![0u8; needed as usize];
        let mut written: u32 = 0;
        // SAFETY: as above, but `out` is a live, exactly `needed`-byte output slice.
        unsafe {
            NCryptEncrypt(
                self.key,
                Some(input),
                Some(padding_ptr),
                Some(out.as_mut_slice()),
                &mut written,
                NCRYPT_PAD_OAEP_FLAG,
            )
        }
        .map_err(|e| prov_err("NCryptEncrypt", &e))?;

        out.truncate(written as usize);
        Ok(SealedBlob(out))
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<SecretBytes> {
        let padding = oaep_padding();
        let padding_ptr = &padding as *const BCRYPT_OAEP_PADDING_INFO as *const c_void;
        let ct = blob.0.as_slice();

        // First call: query the maximum plaintext size.
        let mut needed: u32 = 0;
        // SAFETY: `self.key` is a live finalized key; `ct` is a live slice; `padding_ptr` points
        // to the live `padding` value; output is `None` (size query); `needed` is a valid
        // out-pointer.
        unsafe {
            NCryptDecrypt(
                self.key,
                Some(ct),
                Some(padding_ptr),
                None,
                &mut needed,
                NCRYPT_PAD_OAEP_FLAG,
            )
        }
        .map_err(|e| prov_err("NCryptDecrypt(size)", &e))?;

        // Second call: decrypt into a transient buffer, then move into a locked SecretBytes.
        let mut transient = vec![0u8; needed as usize];
        let mut written: u32 = 0;
        // SAFETY: as above, but `transient` is a live, exactly `needed`-byte output slice.
        let res = unsafe {
            NCryptDecrypt(
                self.key,
                Some(ct),
                Some(padding_ptr),
                Some(transient.as_mut_slice()),
                &mut written,
                NCRYPT_PAD_OAEP_FLAG,
            )
        };
        if let Err(e) = res {
            transient.zeroize();
            return Err(prov_err("NCryptDecrypt", &e));
        }

        let plaintext = SecretBytes::from_exact(&transient[..written as usize]);
        transient.zeroize(); // scrub the transient plaintext copy
        Ok(plaintext)
    }

    fn describe(&self) -> String {
        "Windows CNG Platform Crypto Provider (TPM-backed, non-exportable RSA-2048 key wrap; \
         device-bound, not PCR-policy-bound)"
            .into()
    }
}

impl Drop for CngPcpProvider {
    fn drop(&mut self) {
        // SAFETY: `key` and `prov` were obtained from successful NCrypt* calls in `open()` and
        // have not been freed elsewhere. `NCryptFreeObject` tolerates being called once per
        // live handle; we never construct a `CngPcpProvider` with invalid handles.
        unsafe {
            let _ = NCryptFreeObject(self.key);
            let _ = NCryptFreeObject(self.prov);
        }
    }
}

#[cfg(all(windows, test))]
mod tests {
    use super::*;
    use crate::secret::SecretBytes;

    #[test]
    fn tpm_seal_unseal_roundtrip_if_available() {
        let p = match CngPcpProvider::open() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("SKIP: no usable platform TPM");
                return;
            }
        };
        let dek = SecretBytes::generate(32);
        let sealed = p.seal(&dek, &[7, 11]).unwrap();
        let out = p.unseal(&sealed).unwrap();
        assert!(dek.ct_eq(&out));
    }
}
