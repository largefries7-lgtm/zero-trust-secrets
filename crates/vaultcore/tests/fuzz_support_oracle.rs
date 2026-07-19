//! Proves the machinery behind the `v2_to_v3_migration` fuzz target on stable.
//!
//! The fuzz target itself needs nightly + libFuzzer and only runs on the Linux CI
//! job, so its ORACLE is duplicated here as an ordinary test: if
//! `fuzz_support::build_v2_image` ever stops producing a genuine, MAC-valid v2
//! image, the fuzz target would silently degrade into testing nothing (every case
//! bailing at the MAC) and still report "no crashes found". This test fails
//! loudly instead.
//!
//! It also stands on its own as regression coverage for the v2 -> v3 migration
//! added in b4f645d.

#![cfg(feature = "fuzzing")]

use vaultcore::vault::{fuzz_support, LockedVault};

fn migrate(pairs: &[(String, Vec<u8>)]) -> vaultcore::vault::Vault {
    let dek = fuzz_support::fixed_dek();
    let image = fuzz_support::build_v2_image(&dek, pairs);
    LockedVault::load_from_bytes(&image)
        .expect("builder must emit a parseable v2 image")
        .unlock_with_dek(dek)
        .expect("builder must emit a MAC-valid v2 image")
}

fn pairs(v: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
    v.iter()
        .map(|(n, val)| (n.to_string(), val.as_bytes().to_vec()))
        .collect()
}

#[test]
fn built_v2_image_parses_as_v2() {
    let dek = fuzz_support::fixed_dek();
    let image = fuzz_support::build_v2_image(&dek, &pairs(&[("email", "hunter2")]));
    let locked = LockedVault::load_from_bytes(&image).expect("parses");
    assert_eq!(
        locked.header().format_version,
        2,
        "the fuzz builder must emit format v2 — if this became v3 the migration \
         target would never exercise the migration path"
    );
}

#[test]
fn migration_round_trips_values() {
    let input = pairs(&[("email", "hunter2"), ("bank", "1234")]);
    let vault = migrate(&input);

    assert_eq!(vault.list(), vec!["email", "bank"], "order must be preserved");
    assert_eq!(vault.get("email").unwrap().expose_str(), "hunter2");
    assert_eq!(vault.get("bank").unwrap().expose_str(), "1234");
}

#[test]
fn migrated_vault_is_v3() {
    let vault = migrate(&pairs(&[("k", "v")]));
    assert_eq!(
        vault.header().format_version,
        vaultcore::vault::FORMAT_VERSION,
        "unlock must re-stamp the header to v3 so the next save upgrades the file"
    );
}

#[test]
fn migration_handles_empty_and_padding_edge_cases() {
    // Sizes chosen around the v3 padding buckets (NAME_BUCKET=64,
    // VALUE_BUCKET=256): empty, exactly-a-bucket, and one-over-a-bucket are
    // where `padded_len`'s div_ceil/max would go wrong.
    let long_name = "n".repeat(64);
    let bucket_value = "v".repeat(252); // 4-byte len prefix + 252 == 256 exactly
    let over_bucket = "v".repeat(253); // one past the bucket
    let input = pairs(&[
        ("", ""),
        (long_name.as_str(), bucket_value.as_str()),
        ("over", over_bucket.as_str()),
    ]);

    let vault = migrate(&input);
    assert_eq!(vault.get("").unwrap().expose_str(), "");
    assert_eq!(vault.get(&long_name).unwrap().expose_str(), bucket_value);
    assert_eq!(vault.get("over").unwrap().expose_str(), over_bucket);
}

#[test]
fn empty_vault_migrates() {
    let vault = migrate(&[]);
    assert!(vault.list().is_empty());
}
