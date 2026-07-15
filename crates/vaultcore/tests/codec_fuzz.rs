//! Property-fuzz the hand-written vault codec against malicious/arbitrary input.
//!
//! The parser is the primary attack surface for a hostile `.ztsv` file. These
//! tests assert the parser is TOTAL: for ANY byte string it returns `Ok` or
//! `Err` but never panics, over-reads, or hangs. A panic here would be a
//! denial-of-service (and, in a library embedding, a potential abort). We do
//! not assert semantic correctness on garbage — only that parsing is safe.

use proptest::prelude::*;
use vaultcore::vault::{LockedVault, VaultHeader};

fn write_temp(bytes: &[u8], tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    // Unique per case to avoid cross-test collisions under parallelism.
    let mut r = [0u8; 8];
    getrandom::getrandom(&mut r).unwrap();
    p.push(format!(
        "ztsv_fuzz_{}_{}_{:016x}.ztsv",
        tag,
        std::process::id(),
        u64::from_le_bytes(r)
    ));
    std::fs::write(&p, bytes).unwrap();
    p
}

proptest! {
    // Header parser must never panic on arbitrary bytes.
    #[test]
    fn header_from_bytes_is_total(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        // Ok or Err are both fine; a panic fails the test.
        let _ = VaultHeader::from_bytes(&data);
    }

    // Full-file loader must never panic on arbitrary bytes.
    #[test]
    fn load_is_total_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let path = write_temp(&data, "arb");
        let _ = LockedVault::load(&path);
        std::fs::remove_file(&path).ok();
    }

    // Structured fuzz: a valid length-prefixed header frame wrapping arbitrary
    // header bytes, plus an arbitrary tail. This reaches deeper into the parser
    // (past the outer framing into the record loop) than pure noise would.
    #[test]
    fn load_is_total_structured(
        magic_ok in any::<bool>(),
        hdr in proptest::collection::vec(any::<u8>(), 0..256),
        n_records in any::<u32>(),
        tail in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut file = Vec::new();
        let mut header = hdr.clone();
        if magic_ok && header.len() >= 4 {
            header[0..4].copy_from_slice(b"ZTSV");
        }
        file.extend_from_slice(&(header.len() as u32).to_le_bytes());
        file.extend_from_slice(&header);
        file.extend_from_slice(&n_records.to_le_bytes()); // possibly enormous
        file.extend_from_slice(&tail);

        let path = write_temp(&file, "struct");
        let _ = LockedVault::load(&path);
        std::fs::remove_file(&path).ok();
    }
}
