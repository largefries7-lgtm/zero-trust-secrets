use super::{KeyProvider, ProviderStatus, SealedBlob};
use crate::crypto::{self, Argon2Params};
use crate::secret::{SecretBytes, SecretString};
use crate::Result;

pub struct RecoveryProvider {
    pass: SecretString,
    params: Argon2Params,
}

impl RecoveryProvider {
    pub fn new(pass: SecretString, params: Argon2Params) -> Self {
        Self { pass, params }
    }
}

impl KeyProvider for RecoveryProvider {
    fn status(&self) -> ProviderStatus {
        ProviderStatus::Available
    }
    fn seal(&self, dek: &SecretBytes, _pcrs: &[u32]) -> Result<SealedBlob> {
        let kek = crypto::derive_kek(&self.pass, &self.params)?;
        Ok(SealedBlob(crypto::aead_seal(&kek, b"recovery-wrap", dek.expose())?))
    }
    fn unseal(&self, blob: &SealedBlob) -> Result<SecretBytes> {
        let kek = crypto::derive_kek(&self.pass, &self.params)?;
        crypto::aead_open(&kek, b"recovery-wrap", &blob.0)
    }
    fn describe(&self) -> String {
        "recovery (Argon2id passphrase escrow)".into()
    }
}
