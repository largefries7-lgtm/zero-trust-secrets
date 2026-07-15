use super::{KeyProvider, ProviderStatus, SealedBlob};
use crate::secret::SecretBytes;
use crate::{Error, Result};

macro_rules! stub {
    ($name:ident, $desc:literal) => {
        pub struct $name;
        impl KeyProvider for $name {
            fn status(&self) -> ProviderStatus {
                ProviderStatus::Unsupported
            }
            fn seal(&self, _d: &SecretBytes, _p: &[u32]) -> Result<SealedBlob> {
                Err(Error::Provider(concat!($desc, " not implemented in this slice").into()))
            }
            fn unseal(&self, _b: &SealedBlob) -> Result<SecretBytes> {
                Err(Error::Provider(concat!($desc, " not implemented in this slice").into()))
            }
            fn describe(&self) -> String {
                $desc.into()
            }
        }
    };
}
stub!(MacStub, "macOS Secure Enclave");
stub!(LinuxStub, "Linux tss-esapi TPM");
