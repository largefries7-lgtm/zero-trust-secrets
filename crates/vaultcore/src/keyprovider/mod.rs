pub mod recovery;
pub mod stubs;

use crate::secret::SecretBytes;
use crate::Result;

pub enum ProviderStatus {
    Available,
    Unsupported,
    Degraded(String),
}
pub struct SealedBlob(pub Vec<u8>);

pub trait KeyProvider {
    fn status(&self) -> ProviderStatus;
    fn seal(&self, dek: &SecretBytes, pcrs: &[u32]) -> Result<SealedBlob>;
    fn unseal(&self, blob: &SealedBlob) -> Result<SecretBytes>;
    fn describe(&self) -> String;
}

pub use recovery::RecoveryProvider;
pub use stubs::{LinuxStub, MacStub};

#[cfg(windows)]
pub mod cng_pcp;
#[cfg(windows)]
pub use cng_pcp::CngPcpProvider;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;
    use crate::secret::{SecretBytes, SecretString};

    #[test]
    fn recovery_seal_unseal_roundtrip() {
        let params = Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [3u8; 16] };
        let p = RecoveryProvider::new(SecretString::from_string("pw".into()), params);
        let dek = SecretBytes::from_exact(&[9u8; 32]);
        let sealed = p.seal(&dek, &[]).unwrap();
        let out = p.unseal(&sealed).unwrap();
        assert!(dek.ct_eq(&out));
    }

    #[test]
    fn recovery_rejects_wrong_passphrase() {
        let params = Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [3u8; 16] };
        let sealed = RecoveryProvider::new(SecretString::from_string("pw".into()), params)
            .seal(&SecretBytes::from_exact(&[9u8; 32]), &[])
            .unwrap();
        let wrong = RecoveryProvider::new(SecretString::from_string("nope".into()), params);
        assert!(wrong.unseal(&sealed).is_err());
    }

    #[test]
    fn stub_is_unsupported() {
        assert!(matches!(MacStub.status(), ProviderStatus::Unsupported));
    }
}
