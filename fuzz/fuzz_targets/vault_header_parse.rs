//! Fuzz the untrusted header parser: `VaultHeader::from_bytes`.
//!
//! The header is the first thing a hostile `.ztsv` gets to control, and it is
//! parsed BEFORE anything is authenticated. Two properties are asserted:
//!
//!   1. Totality — any byte string yields `Ok` or `Err`, never a panic, an
//!      over-read, or an unbounded allocation driven by a length field.
//!   2. Canonical re-serialization — if a header parses, serializing it and
//!      re-parsing must produce the same bytes. A parser/serializer disagreement
//!      here is a security bug, not a cosmetic one: `mac_input` MACs
//!      `to_bytes()`, so a header that round-trips to different bytes would
//!      authenticate something other than what was on disk.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultcore::vault::VaultHeader;

fuzz_target!(|data: &[u8]| {
    let Ok(header) = VaultHeader::from_bytes(data) else {
        // Rejecting malformed input is the expected outcome, not a failure.
        return;
    };

    // The parse succeeded, so the header is now in canonical form. Serializing
    // and re-parsing must be a fixed point. (We compare against `to_bytes()`
    // rather than the original `data`, because trailing bytes after the header
    // are legitimately ignored by the parser and would not be reproduced.)
    let once = header.to_bytes();
    let reparsed = VaultHeader::from_bytes(&once)
        .expect("a header serialized from a parsed header must re-parse");
    let twice = reparsed.to_bytes();

    assert_eq!(
        once, twice,
        "header serialization is not idempotent: the MAC would cover different \
         bytes than the ones that were parsed"
    );
});
