use proptest::prelude::*;
use vaultcore::crypto::Argon2Params;
use vaultcore::secret::{SecretBytes, SecretString};
use vaultcore::vault::{Vault, VaultHeader};

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

proptest! {
    #[test]
    fn arbitrary_values_survive_roundtrip(name in "[a-z]{1,12}", val in ".{0,64}") {
        prop_assume!(!name.is_empty());

        let dek = SecretBytes::from_exact(&[5u8; 32]);
        let mut vault = Vault::new_unlocked(dek, test_header());

        vault.add(&name, SecretString::from_string(val.clone())).unwrap();
        let got = vault.get(&name).unwrap();

        prop_assert_eq!(got.expose_str(), val.as_str());
    }
}
