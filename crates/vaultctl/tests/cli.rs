//! Process-spawning integration tests for the stateless `vaultctl` CLI.
//! The DEK is never persisted, so `add`/`get` are passed the unlock
//! passphrase on each invocation (non-TPM `--allow-no-tpm` vault).

use std::process::Command;

/// A passphrase that clears the single-factor strength floor (mixed classes, 22
/// chars). Vault creation now rejects weak passphrases, so the fixtures use this.
const PW: &str = "Tq7!vK2m-Zp9x_Lw3r#Hs6";

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_vaultctl"));
    // DEBUG-only escape hatch: use a cheap fixed Argon2 cost so `init` doesn't pay
    // the (deliberately expensive) production calibration on every spawn. Release
    // binaries ignore this env var entirely.
    c.env("ZTSV_KDF_FIXED_FOR_TESTS", "1");
    c
}

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ztsv-cli-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Pull the one-time recovery code out of `init --recovery` stdout.
fn extract_recovery_code(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("recovery code: "))
        .expect("init --recovery should print a recovery code")
        .trim()
        .to_string()
}

#[test]
fn init_add_get_list_roundtrip() {
    let dir = unique_dir("roundtrip");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", PW])
        .status()
        .unwrap()
        .success());
    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "hunter2", "--passphrase", PW])
        .status()
        .unwrap()
        .success());

    let out = bin()
        .args(["--vault", vs, "get", "email", "--passphrase", PW])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("hunter2"));

    let list = bin().args(["--vault", vs, "list", "--passphrase", PW]).output().unwrap();
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
fn weak_passphrase_is_rejected_on_init() {
    let dir = unique_dir("weakpw");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    // A common passphrase must be refused, and no vault file left behind.
    let out = bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", "password1"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).to_lowercase().contains("weak"));
    assert!(!v.exists(), "a rejected init must not leave a vault file");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn recovery_code_unlocks_and_seal_status_reports_it() {
    let dir = unique_dir("recovery");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    // Vault with an opt-in recovery escrow: a 128-bit code is generated + printed.
    let init = bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", PW, "--recovery"])
        .output()
        .unwrap();
    assert!(init.status.success());
    let code = extract_recovery_code(&String::from_utf8_lossy(&init.stdout));

    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "hunter2", "--passphrase", PW])
        .status()
        .unwrap()
        .success());

    // Unlock via the recovery code (single factor) — lower-cased to prove the
    // CLI normalizes user input.
    let out = bin()
        .args(["--vault", vs, "get", "email", "--recovery", "--recovery-code", &code.to_lowercase()])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("hunter2"));

    // Wrong recovery code fails.
    assert!(!bin()
        .args([
            "--vault", vs, "get", "email", "--recovery", "--recovery-code",
            "0000-0000-0000-0000-0000-0000-00",
        ])
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
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", PW])
        .status()
        .unwrap()
        .success());
    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "old", "--passphrase", PW])
        .status()
        .unwrap()
        .success());

    // A second plain `add` of the same name must FAIL (no silent shadowing)...
    assert!(!bin()
        .args(["--vault", vs, "add", "email", "--value", "new", "--passphrase", PW])
        .status()
        .unwrap()
        .success());
    // ...and the original value is untouched.
    let out = bin()
        .args(["--vault", vs, "get", "email", "--passphrase", PW])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("old"));

    // `add --force` rotates the value in place.
    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "new", "--force", "--passphrase", PW])
        .status()
        .unwrap()
        .success());
    let out = bin()
        .args(["--vault", vs, "get", "email", "--passphrase", PW])
        .output()
        .unwrap();
    let got = String::from_utf8_lossy(&out.stdout);
    assert!(got.contains("new"), "expected rotated value, got: {got}");
    // Exactly one record named `email` remains (no duplicate left behind).
    let list = bin().args(["--vault", vs, "list", "--passphrase", PW]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&list.stdout).matches("email").count(), 1);

    // `rm` deletes the record; a subsequent `get` fails.
    assert!(bin()
        .args(["--vault", vs, "rm", "email", "--passphrase", PW])
        .status()
        .unwrap()
        .success());
    assert!(!bin()
        .args(["--vault", vs, "get", "email", "--passphrase", PW])
        .status()
        .unwrap()
        .success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn recovery_code_requires_recovery_flag() {
    let dir = unique_dir("requires-recovery");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", PW])
        .status()
        .unwrap()
        .success());

    // Passing --recovery-code without --recovery must be rejected by clap, not
    // silently ignored (which could mislead the user about which factor is used).
    assert!(!bin()
        .args(["--vault", vs, "get", "email", "--recovery-code", "XXXX-XXXX"])
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
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", PW])
        .status()
        .unwrap()
        .success());
    // second init on the same path must fail (do not overwrite).
    assert!(!bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", PW])
        .status()
        .unwrap()
        .success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn list_requires_unlock_and_shows_authenticated_names() {
    let dir = unique_dir("list-unlock");
    let v = dir.join("v.ztsv");
    let vs = v.to_str().unwrap();

    assert!(bin()
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", PW])
        .status()
        .unwrap()
        .success());
    assert!(bin()
        .args(["--vault", vs, "add", "email", "--value", "x", "--passphrase", PW])
        .status()
        .unwrap()
        .success());

    // As of format v3 names are encrypted, so `list` unlocks: with the passphrase
    // the (decrypted + authenticated) name is shown on clean stdout.
    let out = bin().args(["--vault", vs, "list", "--passphrase", PW]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("email"));

    // Without the correct passphrase, names cannot be decrypted -> list fails.
    assert!(!bin()
        .args(["--vault", vs, "list", "--passphrase", "wrong"])
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
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", PW])
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
        .args(["--vault", vs, "init", "--allow-no-tpm", "--passphrase", PW])
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
