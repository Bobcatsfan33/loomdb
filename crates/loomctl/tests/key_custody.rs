//! Trust-root custody at the command boundary: the rotation sequence, and what each step changes.
//!
//! These run the real `loomctl` binary against a real register file, because that is what an
//! operator runs at 3am and what a ceremony will be conducted with. A rotation that is correct as a
//! function and wrong as a command is wrong.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use loom_branch::{Loom, BACKUP_MANIFEST_FILE};
use loom_core::{ActorId, Record, SessionId, TenantId, Value, WriteEnvelope};

const TENANT: &str = "acme";

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_loomctl"))
        .args(arguments)
        .output()
        .expect("loomctl must execute")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn text(path: &Path) -> String {
    path.to_str().expect("UTF-8 path").to_string()
}

fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// Write a private key at a mode a signer will accept.
fn private_key_file(dir: &Path, name: &str, seed: u8) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, hex(&key(seed).to_bytes())).expect("key writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }
    path
}

fn public_key_file(dir: &Path, name: &str, seed: u8) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, hex(key(seed).verifying_key().as_bytes())).expect("key writes");
    path
}

/// A register holding one active backup-root key.
fn seed_register(dir: &Path, key_id: &str, seed: u8) -> PathBuf {
    let path = dir.join("trust-roots.json");
    let body = format!(
        r#"{{"schemaVersion":1,"roots":[{{"keyId":"{key_id}","role":"backup-root",
           "algorithm":"ed25519","publicKey":"{}","backend":"software","status":"active",
           "generation":1,"ceremony":{{"reference":"CEREMONY-1","approvals":[
             {{"approver":"pki-officer","atUnix":1800000000}},
             {{"approver":"security-lead","atUnix":1800000000}}]}}}}]}}"#,
        hex(key(seed).verifying_key().as_bytes())
    );
    std::fs::write(&path, body).expect("register writes");
    path
}

fn inspect(register: &Path) -> serde_json::Value {
    let output = run(&["keys", "inspect", "--trust-roots", &text(register)]);
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("json")
}

fn status_of(register: &Path, key_id: &str) -> String {
    inspect(register)["roots"]
        .as_array()
        .expect("roots")
        .iter()
        .find(|root| root["key_id"] == key_id)
        .unwrap_or_else(|| panic!("{key_id} is registered"))["status"]
        .as_str()
        .expect("status")
        .to_string()
}

// ── the rotation sequence ────────────────────────────────────────────────────────────────────────

/// **The whole sequence, as commands, with the state after each step asserted.**
#[test]
fn expand_activate_drill_revoke_at_the_command_boundary() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let register = seed_register(dir.path(), "backup-2026-q3", 1);
    let next_public = public_key_file(dir.path(), "next.pub", 2);
    let next_private = private_key_file(dir.path(), "next.key", 2);

    // EXPAND — staged, and authorizing nothing.
    let expanded = run(&[
        "keys",
        "expand",
        "--trust-roots",
        &text(&register),
        "--role",
        "backup-root",
        "--key-id",
        "backup-2026-q4",
        "--public-key-file",
        &text(&next_public),
        "--generation",
        "2",
        "--ceremony",
        "CEREMONY-2026-Q4",
        "--approver",
        "pki-officer",
        "--approver",
        "security-lead",
    ]);
    assert!(expanded.status.success(), "{expanded:?}");
    assert_eq!(status_of(&register, "backup-2026-q4"), "pending");
    assert_eq!(status_of(&register, "backup-2026-q3"), "active");

    // ACTIVATE — signing moves; the superseded key retires and keeps verifying.
    let activated = run(&[
        "keys",
        "activate",
        "--trust-roots",
        &text(&register),
        "--role",
        "backup-root",
        "--key-id",
        "backup-2026-q4",
    ]);
    assert!(activated.status.success(), "{activated:?}");
    assert_eq!(status_of(&register, "backup-2026-q4"), "active");
    assert_eq!(status_of(&register, "backup-2026-q3"), "retired");

    // DRILL — the new key signs, custody accepts it, and the receipt says which backend produced it.
    let drilled = run(&[
        "keys",
        "drill",
        "--trust-roots",
        &text(&register),
        "--role",
        "backup-root",
        "--signing-key-file",
        &text(&next_private),
    ]);
    assert!(drilled.status.success(), "{drilled:?}");
    let report: serde_json::Value = serde_json::from_slice(&drilled.stdout)?;
    assert_eq!(report["signed_by"], "backup-2026-q4");
    assert_eq!(report["backend"], "software");
    assert!(
        report["custody_claim"]
            .as_str()
            .unwrap_or_default()
            .contains("EXT-HSM remains open"),
        "a software drill must not read as a satisfied hardware gate: {report}"
    );

    // REVOKE — and only now does the old key stop verifying.
    let revoked = run(&[
        "keys",
        "revoke",
        "--trust-roots",
        &text(&register),
        "--role",
        "backup-root",
        "--key-id",
        "backup-2026-q3",
        "--reason",
        "superseded at the 2026-Q4 ceremony",
    ]);
    assert!(revoked.status.success(), "{revoked:?}");
    assert_eq!(status_of(&register, "backup-2026-q3"), "revoked");
    Ok(())
}

/// One person cannot make a key authoritative.
#[test]
fn a_single_approver_cannot_activate_a_key() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let register = seed_register(dir.path(), "backup-2026-q3", 1);
    let next_public = public_key_file(dir.path(), "next.pub", 2);

    assert!(run(&[
        "keys",
        "expand",
        "--trust-roots",
        &text(&register),
        "--role",
        "backup-root",
        "--key-id",
        "backup-2026-q4",
        "--public-key-file",
        &text(&next_public),
        "--generation",
        "2",
        "--ceremony",
        "CEREMONY-2026-Q4",
        "--approver",
        "pki-officer",
    ])
    .status
    .success());

    let output = run(&[
        "keys",
        "activate",
        "--trust-roots",
        &text(&register),
        "--role",
        "backup-root",
        "--key-id",
        "backup-2026-q4",
    ]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("distinct approvers"),
        "{output:?}"
    );
    Ok(())
}

/// Sealing a role is a real incident posture, and it must be asked for explicitly.
#[test]
fn revoking_the_last_key_needs_an_explicit_seal() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let register = seed_register(dir.path(), "backup-2026-q3", 1);

    let refused = run(&[
        "keys",
        "revoke",
        "--trust-roots",
        &text(&register),
        "--role",
        "backup-root",
        "--key-id",
        "backup-2026-q3",
        "--reason",
        "compromised",
    ]);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("seals the role"),
        "{refused:?}"
    );

    let sealed = run(&[
        "keys",
        "revoke",
        "--trust-roots",
        &text(&register),
        "--role",
        "backup-root",
        "--key-id",
        "backup-2026-q3",
        "--reason",
        "compromised",
        "--seal-role",
    ]);
    assert!(sealed.status.success(), "{sealed:?}");
    Ok(())
}

/// A drill cannot be run with a key custody says may not sign.
#[test]
fn a_drill_refuses_a_key_that_is_not_the_active_signer() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let register = seed_register(dir.path(), "backup-2026-q3", 1);
    let wrong = private_key_file(dir.path(), "wrong.key", 9);

    let output = run(&[
        "keys",
        "drill",
        "--trust-roots",
        &text(&register),
        "--role",
        "backup-root",
        "--signing-key-file",
        &text(&wrong),
    ]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("does not match"),
        "{output:?}"
    );
    Ok(())
}

// ── the backup role, verified through custody ────────────────────────────────────────────────────

/// **Revocation reaches the backup path.** The same backup verifies before the revocation and is
/// refused after it, with nothing about the backup or its signature having changed.
#[test]
fn revoking_the_backup_root_stops_a_previously_good_backup_verifying(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("store");
    {
        let db = Loom::open(&store, TenantId::new(TENANT))?;
        let (session, token) = db.open_session_named(SessionId::new("incident"))?;
        db.write(
            &token,
            &session.branch,
            b"status".to_vec(),
            Record::Value(Value::Text("contained".into())),
            &WriteEnvelope::new(
                ActorId::new("operator"),
                session.id,
                session.branch.clone(),
                "seed",
            ),
        )?;
    }
    let signing = private_key_file(dir.path(), "backup.key", 1);
    let register = seed_register(dir.path(), "backup-2026-q3", 1);
    let backup = dir.path().join("backup-1");

    assert!(run(&[
        "backup-signed",
        "--path",
        &text(&store),
        "--tenant",
        TENANT,
        "--out",
        &text(&backup),
        "--signing-key-file",
        &text(&signing),
        "--key-id",
        "backup-2026-q3",
    ])
    .status
    .success());

    // Before: custody accepts it.
    let before = run(&[
        "verify-backup-signed",
        "--path",
        &text(&backup),
        "--trust-roots",
        &text(&register),
    ]);
    assert!(before.status.success(), "{before:?}");
    assert!(
        String::from_utf8_lossy(&before.stderr).contains("backup-2026-q3"),
        "verification must name the trust root that accepted it: {before:?}"
    );
    assert!(backup.join(BACKUP_MANIFEST_FILE).is_file());

    // Revoke — sealing the role, because this deployment has one backup key.
    assert!(run(&[
        "keys",
        "revoke",
        "--trust-roots",
        &text(&register),
        "--role",
        "backup-root",
        "--key-id",
        "backup-2026-q3",
        "--reason",
        "key compromise drill",
        "--seal-role",
    ])
    .status
    .success());

    // After: the identical backup, the identical signature, refused — and named as a revocation
    // rather than as a bad signature, because those are different incidents.
    let after = run(&[
        "verify-backup-signed",
        "--path",
        &text(&backup),
        "--trust-roots",
        &text(&register),
    ]);
    assert!(!after.status.success(), "{after:?}");
    let stderr = String::from_utf8_lossy(&after.stderr);
    assert!(stderr.contains("REVOKED"), "{after:?}");
    assert!(
        stderr.contains("key compromise drill"),
        "the refusal must carry the reason: {after:?}"
    );
    Ok(())
}

/// A backup key is not a release key. Roles are separate authorities.
#[test]
fn a_register_without_the_backup_role_cannot_verify_a_backup(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("store");
    drop(Loom::open(&store, TenantId::new(TENANT))?);
    let signing = private_key_file(dir.path(), "backup.key", 1);
    let backup = dir.path().join("backup-1");
    assert!(run(&[
        "backup-signed",
        "--path",
        &text(&store),
        "--tenant",
        TENANT,
        "--out",
        &text(&backup),
        "--signing-key-file",
        &text(&signing),
        "--key-id",
        "backup-2026-q3",
    ])
    .status
    .success());

    let register = dir.path().join("release-only.json");
    std::fs::write(
        &register,
        seed_register(dir.path(), "backup-2026-q3", 1)
            .to_str()
            .map(|path| std::fs::read_to_string(path).expect("read"))
            .expect("path")
            .replace("backup-root", "release"),
    )?;

    let output = run(&[
        "verify-backup-signed",
        "--path",
        &text(&backup),
        "--trust-roots",
        &text(&register),
    ]);
    assert!(!output.status.success(), "{output:?}");
    Ok(())
}
