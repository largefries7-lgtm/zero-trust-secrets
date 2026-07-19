//! Fuzz the legacy v2 -> v3 migration performed by `LockedVault::unlock_with_dek`.
//!
//! Why this target is built from a BUILDER rather than raw bytes:
//!
//! The migration path sits behind two gates a byte-oriented fuzzer cannot pass —
//! the v2 header MAC (`verify_mac_v2`) and then a per-record AEAD open. Feeding
//! arbitrary v2-framed bytes therefore only ever exercises "MAC rejects garbage",
//! which the existing proptests already cover, and never reaches a single line of
//! actual migration logic. Instead we let the fuzzer choose record *content* and
//! seal it correctly under a known DEK (`vault::fuzz_support`, behind the
//! `fuzzing` feature). Arbitrary semantics, valid cryptography — which is where
//! the reachable bugs in a migration actually are.
//!
//! The oracle is a full round-trip, not merely absence of panics:
//! every (name, value) that went into the v2 image must come back out of the
//! migrated v3 vault, intact and in order. That catches silent data loss,
//! misordering, off-by-one padding, and AAD/subkey mix-ups between the two
//! formats — none of which would panic.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use vaultcore::vault::{fuzz_support, LockedVault};

#[derive(Arbitrary, Debug)]
struct Input {
    /// (name, value). Values are `String` rather than `Vec<u8>` because
    /// `Vault::get` returns a `SecretString` — a non-UTF-8 value could not be
    /// read back, so it could not participate in the round-trip oracle.
    records: Vec<(String, String)>,
}

fuzz_target!(|input: Input| {
    // Keep each case cheap so the fuzzer spends its budget on shapes, not on
    // Argon2-free but still non-trivial AEAD work over huge inputs.
    if input.records.len() > 32 {
        return;
    }

    // A v2 file with duplicate record names is malformed in a way the v3 model
    // has no answer for (`get` resolves by name and would return an arbitrary
    // one). The round-trip property is undefined there, so skip it rather than
    // assert something false. Worth a separate look — see fuzz/README.md.
    let mut seen = HashSet::new();
    if !input.records.iter().all(|(n, _)| seen.insert(n.clone())) {
        return;
    }

    let pairs: Vec<(String, Vec<u8>)> = input
        .records
        .iter()
        .map(|(n, v)| (n.clone(), v.clone().into_bytes()))
        .collect();

    let dek = fuzz_support::fixed_dek();
    let image = fuzz_support::build_v2_image(&dek, &pairs);

    // The builder emits a well-formed v2 image, so BOTH of these must succeed.
    // A failure is a genuine finding, hence `expect` rather than `let else`.
    let locked = LockedVault::load_from_bytes(&image)
        .expect("a v2 image built by fuzz_support must parse");
    let vault = locked
        .unlock_with_dek(dek)
        .expect("a MAC-valid v2 image must authenticate and migrate");

    // Every record survived migration, in order.
    let names: Vec<&str> = vault.list();
    let expected: Vec<&str> = input.records.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, expected, "migration lost, added, or reordered records");

    // Every value decrypts back to exactly what went in, under the v3 scheme.
    for (name, value) in &input.records {
        let got = vault
            .get(name)
            .expect("a migrated record must be readable under the v3 scheme");
        assert_eq!(
            got.expose_str(),
            value.as_str(),
            "value corrupted by the v2 -> v3 re-encryption"
        );
    }
});
