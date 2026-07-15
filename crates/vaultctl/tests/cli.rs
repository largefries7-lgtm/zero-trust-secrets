//! Process-spawning integration tests for the stateless `vaultctl` CLI.
//! The DEK is never persisted, so `add`/`get` are passed the unlock
//! passphrase on each invocation (non-TPM `--allow-no-tpm` vault).

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vaultctl"))
}

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ztsv-cli-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn init_add_get_list_roundtrip() {
    let dir = unique_dir("roundtrip");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());
    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "hunter2", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());

    let out = bin()
        .args(["--vault", vs, "get", "email", "--passphrase", "pw"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("hunter2"));

    let list = bin().args(["--vault", vs, "list"]).output().unwrap();
    assert!(list.status.success());
    assert!(String::from_utf8_lossy(&list.stdout).contains("email"));

    // wrong passphrase fails (non-zero exit).
    assert!(!bin()
        .args(["--vault", vs, "get", "email", "--passphrase", "wrong"])
        .status()
        .unwrap()
        .success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn recovery_escrow_unlocks_and_seal_status_reports_it() {
    let dir = unique_dir("recovery");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    // Vault with an opt-in recovery escrow (separate recovery passphrase).
    assert!(bin()
        .args([
            "--vault", vs, "init", "--allow-no-tpm", "--passphrase", "unlockpw", "--recovery",
            "--recovery-passphrase", "recpw",
        ])
        .status()
        .unwrap()
        .success());
    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "hunter2", "--passphrase", "unlockpw"])
        .status()
        .unwrap()
        .success());

    // Unlock via the recovery escrow (single factor).
    let out = bin()
        .args(["--vault", vs, "get", "email", "--recovery", "--recovery-passphrase", "recpw"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("hunter2"));

    // Wrong recovery passphrase fails.
    assert!(!bin()
        .args(["--vault", vs, "get", "email", "--recovery", "--recovery-passphrase", "wrong"])
        .status()
        .unwrap()
        .success());

    // seal-status reports the escrow.
    let st = bin().args(["--vault", vs, "seal-status"]).output().unwrap();
    assert!(String::from_utf8_lossy(&st.stdout).contains("recovery_escrow: true"));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn add_rejects_duplicate_force_replaces_and_rm_removes() {
    let dir = unique_dir("dup-force-rm");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());
    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "old", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());

    // A second plain `add` of the same name must FAIL (no silent shadowing)...
    assert!(!bin()
        .args(["--vault", vs, "add", "email", "--value", "new", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());
    // ...and the original value is untouched.
    let out = bin()
        .args(["--vault", vs, "get", "email", "--passphrase", "pw"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("old"));

    // `add --force` rotates the value in place.
    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "new", "--force", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());
    let out = bin()
        .args(["--vault", vs, "get", "email", "--passphrase", "pw"])
        .output()
        .unwrap();
    let got = String::from_utf8_lossy(&out.stdout);
    assert!(got.contains("new"), "expected rotated value, got: {got}");
    // Exactly one record named `email` remains (no duplicate left behind).
    let list = bin().args(["--vault", vs, "list"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&list.stdout).matches("email").count(), 1);

    // `rm` deletes the record; a subsequent `get` fails.
    assert!(bin()
        .args(["--vault", vs, "rm", "email", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());
    assert!(!bin()
        .args(["--vault", vs, "get", "email", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn init_recovery_passphrase_requires_recovery_flag() {
    let dir = unique_dir("requires-recovery");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    // Passing --recovery-passphrase without --recovery must be rejected, not
    // silently ignored (which would leave the user believing they set up an
    // escrow that does not exist).
    assert!(!bin()
        .args([
            "--vault", vs, "init", "--allow-no-tpm", "--passphrase", "pw",
            "--recovery-passphrase", "recpw",
        ])
        .status()
        .unwrap()
        .success());
    assert!(!v.exists(), "no vault should be created on a rejected init");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn init_refuses_to_clobber_existing_vault() {
    let dir = unique_dir("clobber");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());
    // second init on the same path must fail (do not overwrite).
    assert!(!bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn list_flags_names_as_unauthenticated_metadata() {
    let dir = unique_dir("list-unauth");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());
    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "x", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());

    let out = bin().args(["--vault", vs, "list"]).output().unwrap();
    assert!(out.status.success());
    // Names stay on clean stdout (pipe-friendly)...
    assert!(String::from_utf8_lossy(&out.stdout).contains("email"));
    // ...and the trust-boundary advisory goes to stderr, so `list` never
    // presents unauthenticated names as if they were verified.
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        stderr.contains("unauthenticated"),
        "list should flag names as unauthenticated; stderr was: {stderr:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn gen_produces_password_of_requested_length() {
    let out = bin().args(["gen", "--len", "24"]).output().unwrap();
    assert!(out.status.success());
    let pw = String::from_utf8_lossy(&out.stdout);
    assert_eq!(pw.trim().len(), 24);
}

#[test]
fn gen_without_symbols_is_alphanumeric_and_exact_length() {
    // Pins the observable behavior of `gen` (used to guard the F7 refactor that
    // generates directly into a page-locked buffer instead of a plain String).
    let out = bin().args(["gen", "--len", "48"]).output().unwrap();
    assert!(out.status.success());
    let pw = String::from_utf8_lossy(&out.stdout);
    let pw = pw.trim();
    assert_eq!(pw.chars().count(), 48);
    assert!(
        pw.chars().all(|c| c.is_ascii_alphanumeric()),
        "default charset must be alphanumeric: {pw}"
    );
}

#[test]
fn seal_status_reports_no_hardware_binding() {
    let dir = unique_dir("sealstatus");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());

    let out = bin().args(["--vault", vs, "seal-status"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("hardware_bound: false"));

    std::fs::remove_dir_all(&dir).ok();
}

/// A vault created with `--allow-no-tpm` is protected only by the recovery
/// passphrase (Argon2id escrow); `seal-status` must not claim TPM/CNG
/// protection for it, even on a TPM-equipped machine where the CNG provider
/// would otherwise open successfully.
#[test]
fn seal_status_recovery_only_does_not_claim_tpm() {
    let dir = unique_dir("sealstatus-recovery-only");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", "pw"])
        .status()
        .unwrap()
        .success());

    let out = bin().args(["--vault", vs, "seal-status"]).output().unwrap();
    assert!(out.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("Platform Crypto"),
        "seal-status must not name the CNG provider for a non-hardware-bound vault: {combined}"
    );
    assert!(
        !combined.contains("TPM-backed"),
        "seal-status must not claim TPM-backed protection for a non-hardware-bound vault: {combined}"
    );
    assert!(
        combined.contains("false") || combined.contains("NO hardware"),
        "seal-status must indicate the vault is not hardware-bound: {combined}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
