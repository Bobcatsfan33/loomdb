use loom_branch::Loom;
use loom_core::{ActorId, Record, SessionId, TenantId, Value, WriteEnvelope};
use std::process::{Command, Output};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_loomctl"))
        .args(arguments)
        .output()
        .expect("loomctl must execute")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn operator_can_inspect_verify_backup_and_restore_without_overwriting(
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let source = parent.path().join("source");
    let backup = parent.path().join("backup");
    let restored = parent.path().join("restored");
    let tenant = TenantId::new("acme");
    {
        let db = Loom::open(&source, tenant)?;
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
                "seed operator smoke test",
            ),
        )?;
    }

    let inspect = run(&[
        "inspect",
        "--path",
        source.to_str().ok_or("source path is not UTF-8")?,
        "--tenant",
        "acme",
    ]);
    assert!(inspect.status.success(), "{inspect:?}");
    let inspection: serde_json::Value = serde_json::from_slice(&inspect.stdout)?;
    assert_eq!(inspection["healthy_to_open"], true);
    assert_eq!(inspection["branch_count"], 2);

    let verify = run(&[
        "verify",
        "--path",
        source.to_str().ok_or("source path is not UTF-8")?,
        "--tenant",
        "acme",
    ]);
    assert!(verify.status.success(), "{verify:?}");
    let verification: serde_json::Value = serde_json::from_slice(&verify.stdout)?;
    assert_eq!(verification["healthy"], true);

    let backup_result = run(&[
        "backup",
        "--path",
        source.to_str().ok_or("source path is not UTF-8")?,
        "--tenant",
        "acme",
        "--out",
        backup.to_str().ok_or("backup path is not UTF-8")?,
    ]);
    assert!(backup_result.status.success(), "{backup_result:?}");

    let verify_backup = run(&[
        "verify-backup",
        "--path",
        backup.to_str().ok_or("backup path is not UTF-8")?,
    ]);
    assert!(verify_backup.status.success(), "{verify_backup:?}");

    let wrong_tenant = run(&[
        "restore",
        "--path",
        backup.to_str().ok_or("backup path is not UTF-8")?,
        "--expected-tenant",
        "other",
        "--out",
        restored.to_str().ok_or("restore path is not UTF-8")?,
    ]);
    assert!(!wrong_tenant.status.success());
    assert!(!restored.exists());

    let restore = run(&[
        "restore",
        "--path",
        backup.to_str().ok_or("backup path is not UTF-8")?,
        "--expected-tenant",
        "acme",
        "--out",
        restored.to_str().ok_or("restore path is not UTF-8")?,
    ]);
    assert!(restore.status.success(), "{restore:?}");

    let overwrite = run(&[
        "restore",
        "--path",
        backup.to_str().ok_or("backup path is not UTF-8")?,
        "--expected-tenant",
        "acme",
        "--out",
        restored.to_str().ok_or("restore path is not UTF-8")?,
    ]);
    assert!(!overwrite.status.success());
    Ok(())
}

#[test]
fn production_backup_commands_require_the_expected_trust_root(
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let source = parent.path().join("source");
    let backup = parent.path().join("backup");
    let restored = parent.path().join("restored");
    let signing_file = parent.path().join("backup-signing.hex");
    let public_file = parent.path().join("backup-public.hex");
    let signing = ed25519_dalek::SigningKey::from_bytes(&[73u8; 32]);
    std::fs::write(&signing_file, format!("{}\n", hex(&signing.to_bytes())))?;
    std::fs::write(
        &public_file,
        format!("{}\n", hex(signing.verifying_key().as_bytes())),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&signing_file, std::fs::Permissions::from_mode(0o600))?;
    }
    let db = Loom::open(&source, TenantId::new("acme"))?;
    drop(db);

    let backup_result = run(&[
        "backup-signed",
        "--path",
        source.to_str().ok_or("source path is not UTF-8")?,
        "--tenant",
        "acme",
        "--out",
        backup.to_str().ok_or("backup path is not UTF-8")?,
        "--signing-key-file",
        signing_file.to_str().ok_or("key path is not UTF-8")?,
        "--key-id",
        "backup-root-2026-q3",
    ]);
    assert!(backup_result.status.success(), "{backup_result:?}");

    let wrong_root = run(&[
        "verify-backup-signed",
        "--path",
        backup.to_str().ok_or("backup path is not UTF-8")?,
        "--public-key-file",
        public_file.to_str().ok_or("public key path is not UTF-8")?,
        "--key-id",
        "retired-root",
    ]);
    assert!(!wrong_root.status.success());

    let restore = run(&[
        "restore-signed",
        "--path",
        backup.to_str().ok_or("backup path is not UTF-8")?,
        "--expected-tenant",
        "acme",
        "--out",
        restored.to_str().ok_or("restore path is not UTF-8")?,
        "--public-key-file",
        public_file.to_str().ok_or("public key path is not UTF-8")?,
        "--key-id",
        "backup-root-2026-q3",
    ]);
    assert!(restore.status.success(), "{restore:?}");
    assert!(restored.is_dir());
    Ok(())
}
