//! Process-spawning integration tests for the stateless `vaultctl` CLI.
//! The DEK is never persisted, so `add`/`get` are passed the recovery
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
        .args(["--vault", vs, "init", "--allow-no-tpm", "--recovery-passphrase", "pw"])
        .status()
        .unwrap()
        .success());
    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "hunter2", "--recovery-passphrase", "pw"])
        .status()
        .unwrap()
        .success());

    let out = bin()
        .args(["--vault", vs, "get", "email", "--recovery-passphrase", "pw"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("hunter2"));

    let list = bin().args(["--vault", vs, "list"]).output().unwrap();
    assert!(list.status.success());
    assert!(String::from_utf8_lossy(&list.stdout).contains("email"));

    // wrong passphrase fails (non-zero exit).
    assert!(!bin()
        .args(["--vault", vs, "get", "email", "--recovery-passphrase", "wrong"])
        .status()
        .unwrap()
        .success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn init_refuses_to_clobber_existing_vault() {
    let dir = unique_dir("clobber");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--recovery-passphrase", "pw"])
        .status()
        .unwrap()
        .success());
    // second init on the same path must fail (do not overwrite).
    assert!(!bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--recovery-passphrase", "pw"])
        .status()
        .unwrap()
        .success());

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
fn seal_status_reports_no_hardware_binding() {
    let dir = unique_dir("sealstatus");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--recovery-passphrase", "pw"])
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
        .args(["--vault", vs, "init", "--allow-no-tpm", "--recovery-passphrase", "pw"])
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
