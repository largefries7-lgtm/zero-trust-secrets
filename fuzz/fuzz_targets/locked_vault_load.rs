//! Fuzz the whole-file framing + record parser: `LockedVault::load_from_bytes`.
//!
//! This is the deepest pre-authentication surface. It walks the outer
//! length-prefixed header frame, then the record count, then a record loop whose
//! shape depends on the attacker-chosen `format_version` (v2 = plaintext name,
//! v3 = encrypted). Nothing here has been authenticated yet — the header MAC is
//! only checked later, at `unlock_with_dek` — so every bound in this path is
//! load-bearing.
//!
//! Specifically watched for:
//!   - memory-amplification: a small file claiming a huge record or PCR count
//!     must not drive a large up-front allocation (hence the "grow as you parse"
//!     comments in the parser).
//!   - `take`/offset arithmetic overflow on hostile length prefixes.
//!   - any panic at all, which in a library embedding is a DoS.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultcore::vault::LockedVault;

fuzz_target!(|data: &[u8]| {
    // `load_from_bytes` is the real parser; `load` is just `fs::read` + this.
    // Driving it directly keeps ~50k exec/s instead of a syscall pair per case.
    let _ = LockedVault::load_from_bytes(data);
});
